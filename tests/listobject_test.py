from datetime import datetime
import botocore
import botocore.session
import inspect
import os
import time
import unittest

from host_port import s3_api_host_port
from libs import command, utility

class ListObject_Test(unittest.TestCase):

    # ======== Construction, setUp, tearDown =========
    bucket_irods_path = '/tempZone/home/alice/alice-bucket'
    bucket_name = 'alice-bucket'
    key = 's3_key2'
    secret_key = 's3_secret_key2'
    s3_api_url = f'http://{s3_api_host_port}'

    def __init__(self, *args, **kwargs):
        super(ListObject_Test, self).__init__(*args, **kwargs)

    @classmethod 
    def setUpClass(cls):

        # create collections/data objects
        utility.make_local_file('f1', 100)
        utility.make_local_file('f2', 200)

        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir1')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/f1')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/d1f1')
        command.assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/d1f2')
        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir1/dir1a')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/dir1a/d1af1')
        command.assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/dir1a/d1af2')
        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir1/dir1b')
        command.assert_command(f'iput f1 {cls.bucket_irods_path}/dir1/dir1b/d1bf1')
        command.assert_command(f'iput f2 {cls.bucket_irods_path}/dir1/dir1b/d1bf2')
        command.assert_command(f'imkdir {cls.bucket_irods_path}/dir2')

    @classmethod 
    def tearDownClass(cls):
        command.assert_command(f'irm -rf {cls.bucket_irods_path}/f1 {cls.bucket_irods_path}/f2 {cls.bucket_irods_path}/dir1 {cls.bucket_irods_path}/dir2')
        os.remove('f1')
        os.remove('f2')

    def setUp(self):
        session = botocore.session.get_session()
        self.client = session.create_client('s3',
                                            use_ssl=False,
                                            endpoint_url=self.s3_api_url,
                                            aws_access_key_id=self.key,
                                            aws_secret_access_key=self.secret_key)
    def tearDown(self):
        pass

    # ======== Helper Functions =========

    # used to assert keys are in the contents list returned by botocore
    # possibly checking the size and LastModified time.
    def assert_key_in_contents_list(self, list_objects_result, key, size=None, lastmodified=None):
        contents_list = list_objects_result['Contents']
        matching_key = None
        matching_size = None
        matching_lastmodified = None
        for entry in contents_list:
            if entry['Key'] == key:
                matching_key = entry['Key']
                matching_size = entry['Size']
                matching_lastmodified = entry['LastModified']
                break
    
        self.assertIsNotNone(matching_key, f'Key not found [{key}]')
        self.assertIsNotNone(matching_size, f'Size not found for key [{key}]')
        self.assertIsNotNone(matching_lastmodified, f'LastModified is not found for key {key}')
        if size != None:
            self.assertEqual(matching_size, size, f'Size does not match for key {key}')
        if lastmodified != None:
            # Only checking year/month/day.  This could fail if the time between
            # writing the file to iRODS and  getting the current datetime object
            # rolled over to a new day.
            self.assertEqual(matching_lastmodified.year, lastmodified.year, f'Year does not match for key {key}') 
            self.assertEqual(matching_lastmodified.month, lastmodified.month, f'Month does not match for key {key}')
            self.assertEqual(matching_lastmodified.day,  lastmodified.day, f'Day does not match for key {key}')
    
    # used to assert keys are in the CommonPrefixes list returned by botocore
    def assert_prefix_in_common_prefixes_list(self, list_objects_result, prefix):
        common_prefixes_list = list_objects_result['CommonPrefixes']
        matching_key = None
        for entry in common_prefixes_list:
            if entry['Prefix'] == prefix:
                matching_key = entry['Prefix']
        self.assertIsNotNone(matching_key, f'Prefix [{prefix}] not found')

    # ======== Tests =========

    def test_botocore_list_with_delimiter_no_prefix(self):
        listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/')
        print(listobjects_result)

        command.assert_command('ils -l %s' % self.bucket_irods_path, 'STDOUT') #debug
        current_time = datetime.now()
        self.assertEqual(len(listobjects_result['Contents']), 1, 'Wrong number of results')
        self.assert_key_in_contents_list(listobjects_result, 'f1', size=100, lastmodified=current_time)

        self.assertEqual(len(listobjects_result['CommonPrefixes']), 2, 'Wrong number of results')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir1/')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir2/')

    def test_botocore_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='dir1/')
        self.assertEqual(len(listobjects_result['Contents']), 2, 'Wrong number of results')
        self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f1', size=100)
        self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f2', size=200)
        self.assertEqual(len(listobjects_result['CommonPrefixes']), 2, 'Wrong number of results')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir1/dir1a/')
        self.assert_prefix_in_common_prefixes_list(listobjects_result, 'dir1/dir1b/')

        listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='dir1/dir1a/')
        print(listobjects_result)
        self.assertEqual(len(listobjects_result['Contents']), 2, 'Wrong number of results')
        self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af1')
        self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af2')

    def test_botocore_list_with_delimiter_prefix_no_slash(self):
        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            command.assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Delimiter='/', Prefix='commonkeyprefix')
            print(listobjects_result)
            self.assertEqual(len(listobjects_result['Contents']), 1, 'Wrong number of results')
            self.assert_key_in_contents_list(listobjects_result, 'commonkeyprefix_f1')
            self.assertEqual(len(listobjects_result['CommonPrefixes']), 1, 'Wrong number of results')
            self.assert_prefix_in_common_prefixes_list(listobjects_result, 'commonkeyprefix_dir/')

        finally:
            # local cleanup
            command.assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    def test_botocore_list_no_delimiter(self):

       # With no delimiter this will return all keys beginning with the common prefix and will descend into all collections

       listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix='di')
       print(listobjects_result)
       self.assertEqual(len(listobjects_result['Contents']), 6, 'Wrong number of results')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f1')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/d1f2')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af1')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1a/d1af2')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1b/d1bf1')
       self.assert_key_in_contents_list(listobjects_result, 'dir1/dir1b/d1bf2')

       # No common prefixes when there isn't a delimiter
       self.assertRaises(KeyError, lambda: listobjects_result['CommonPrefixes'])

    def test_botocore_list_nothing_found(self):
       listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix='doesnotexist')
       print(listobjects_result)
       self.assertRaises(KeyError, lambda: listobjects_result['Contents'])

    def test_botocore_list_object_with_reserved_characters_in_name(self):
        for character in ['+', ' ', '$', '@', ',', ':', ';', '=', '?', '&']:
            with self.subTest(f"character:[{character}]"):
                put_filename = f'{inspect.currentframe().f_code.co_name}__{character}.data'
                logical_path = f'{self.bucket_irods_path}/{put_filename}'

                try:
                    utility.make_arbitrary_file(put_filename, 100*1024)
                    command.assert_command(['iput', put_filename, logical_path])
                    listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name)
                    print(listobjects_result)
                    self.assertGreater(len(listobjects_result['Contents']), 6, 'Wrong number of results')
                    self.assert_key_in_contents_list(listobjects_result, put_filename)

                finally:
                    command.assert_command(['ils', '-l', self.bucket_irods_path], 'STDOUT') # debugging
                    if os.path.exists(put_filename):
                        os.remove(put_filename)
                    command.assert_command(['irm', '-f', logical_path])

    def test_aws_list_with_delimiter_no_prefix(self):
        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/',
                'STDOUT_MULTILINE', ['f1', 'dir1/', 'dir2/'])

    def test_aws_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/dir1/',
                'STDOUT_MULTILINE', ['d1f1', 'd1f2', 'dir1a/', 'dir1b/'])

        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/dir1/dir1a/',
                'STDOUT_MULTILINE', ['d1af1', 'd1af2'])

    def test_aws_list_with_delimiter_prefix_no_slash(self):

        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            command.assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls s3://{self.bucket_name}/commonkeyprefix',
                    'STDOUT_MULTILINE', ['commonkeyprefix_f1', 'commonkeyprefix_dir'])

        finally:
            # local cleanup
            command.assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    def test_aws_list_no_delimiter(self):

        # With no delimiter, it is simply a key prefix search.  Since the delimiter does not exist, the search will 
        # descend into all objects.
        command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls --recursive s3://{self.bucket_name}/di',
                'STDOUT_MULTILINE', ['dir1/d1f1', 'dir1/d1f2', 'dir1/dir1a/d1af1', 'dir1/dir1a/d1af2', 'dir1/dir1b/d1bf1', 'dir1/dir1b/d1bf2'])

    def test_aws_list_nothing_found(self):
        _, out, _ = command.assert_command(f'aws --profile s3_api_alice --endpoint-url {self.s3_api_url} s3 ls --recursive s3://{self.bucket_name}/doesnotexist')
        self.assertEqual(len(out), 0)

    def test_aws_list_object_with_reserved_characters_in_name(self):
        for character in ['+', ' ', '$', '@', ',', ':', ';', '=', '?', '&']:
            with self.subTest(f"character:[{character}]"):
                put_filename = f'{inspect.currentframe().f_code.co_name}__{character}.data'
                logical_path = f'{self.bucket_irods_path}/{put_filename}'

                try:
                    utility.make_arbitrary_file(put_filename, 100*1024)
                    command.assert_command(['iput', put_filename, logical_path])
                    command.assert_command(
                        [
                            'aws',
                            '--profile',
                            's3_api_alice',
                            '--endpoint-url',
                            self.s3_api_url,
                            's3',
                            'ls',
                            f's3://{self.bucket_name}'
                        ],
                        'STDOUT',
                        put_filename)

                finally:
                    command.assert_command(['ils', '-l', self.bucket_irods_path], 'STDOUT') # debugging
                    if os.path.exists(put_filename):
                        os.remove(put_filename)
                    command.assert_command(['irm', '-f', logical_path])

    def test_mc_list_with_delimiter_no_prefix(self):
        command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/',
                'STDOUT_MULTILINE', ['f1', 'dir1/', 'dir2/'])

    def test_mc_list_with_delimiter_prefix_ending_with_slash(self):

        # With a delimiter and ending in a slash, this works just like a directory listing
        # Example:   A search for prefix "dir1/" will only show collections and files directly
        # under dir1.
        command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/dir1/',
                'STDOUT_MULTILINE', ['d1f1', 'd1f2', 'dir1a/', 'dir1b/'])

        command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/dir1/dir1a/',
                'STDOUT_MULTILINE', ['d1af1', 'd1af2'])

    def test_mc_list_with_delimiter_prefix_no_slash(self):

        try:
            # With a delimiter and not ending in a slash, this will return all keys beginning with the common
            # prefix but will not descend into collections
            command.assert_command(f'imkdir {self.bucket_irods_path}/commonkeyprefix_dir')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_f1')
            command.assert_command(f'iput f1 {self.bucket_irods_path}/commonkeyprefix_dir/f1')  # this one will not show up in this query

            command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/commonkeyprefix',
                    'STDOUT_MULTILINE', ['commonkeyprefix_f1', 'commonkeyprefix_dir'])

        finally:
            # local cleanup
            command.assert_command(f'irm -rf {self.bucket_irods_path}/commonkeyprefix_dir {self.bucket_irods_path}/commonkeyprefix_f1')

    @unittest.skip('mc client is setting a delimiter even with the --recursive flag set')
    def test_mc_list_no_delimiter(self):
        pass

    def test_mc_list_nothing_found(self):
        _, out, _ = command.assert_command(f'mc ls s3-api-alice/{self.bucket_name}/doesnotexist')
        self.assertEqual(len(out), 0)

    def test_mc_list_object_with_reserved_characters_in_name(self):
        for character in ['+', ' ', '$', '@', ',', ':', ';', '=', '?', '&']:
            with self.subTest(f"character:[{character}]"):
                put_filename = f'{inspect.currentframe().f_code.co_name}__{character}.data'
                logical_path = f'{self.bucket_irods_path}/{put_filename}'

                try:
                    utility.make_arbitrary_file(put_filename, 100*1024)
                    command.assert_command(['iput', put_filename, logical_path])
                    command.assert_command(['mc', 'ls', f's3-api-alice/{self.bucket_name}/'], 'STDOUT', put_filename)

                finally:
                    command.assert_command(['ils', '-l', self.bucket_irods_path], 'STDOUT') # debugging
                    if os.path.exists(put_filename):
                        os.remove(put_filename)
                    command.assert_command(['irm', '-f', logical_path])

    def test_list_object_with_multiple_replicas_only_shows_one_s3_object_per_irods_object__issue_223(self):
        test_resc = "newResc"
        collection_name = 'issue_223_coll'
        put_filename = 'issue_223.data'
        collection_path = f'{self.bucket_irods_path}/{collection_name}'
        logical_path = f'{collection_path}/{put_filename}'
        sleep_time_in_seconds = 2
        original_size_in_bytes = 100
        updated_size_in_bytes = 101

        try:
            # Create a test collection.
            command.assert_command(['imkdir', collection_path])

            # Create a test data object.
            utility.make_arbitrary_file(put_filename, original_size_in_bytes)
            command.assert_command(['iput', put_filename, logical_path])

            # Replicate to the test resource so that there are multiple replicas.
            command.assert_command(['irepl', '-R', test_resc, logical_path])

            # Sleep for some time, then touch one of the replicas so we have a stale replica with a different mtime.
            time.sleep(sleep_time_in_seconds)
            utility.make_arbitrary_file(put_filename, updated_size_in_bytes)
            command.assert_command(['iput', '-R', test_resc, '-f', put_filename, logical_path])

            # Get mtime and status for each replica.
            query = "select DATA_MODIFY_TIME, DATA_REPL_STATUS where COLL_NAME = '{}' and DATA_NAME = '{}' and DATA_REPL_NUM = '{}'"
            replica_0_mtime, replica_0_status = command.assert_command(
                ['iquest', '%s\n%s', query.format( os.path.dirname(logical_path), os.path.basename(logical_path), str(0))],
                'STDOUT'
            )[1].strip().split('\n')
            replica_1_mtime, replica_1_status = command.assert_command(
                ['iquest', '%s\n%s', query.format( os.path.dirname(logical_path), os.path.basename(logical_path), str(1))],
                'STDOUT'
            )[1].strip().split('\n')

            # Ensure that the system metadata is in the expected state.
            self.assertEqual(str(0), replica_0_status)
            self.assertEqual(str(1), replica_1_status)
            self.assertGreater(int(replica_1_mtime), int(replica_0_mtime))

            # Confirm that the object is only listed once and uses info from the most-recently-updated replica.

            mc_targets = [
                f's3-api-alice/{self.bucket_name}/{collection_name}/{put_filename}',
                f's3-api-alice/{self.bucket_name}/{collection_name}/'
            ]
            for target in mc_targets:
                with self.subTest(f'mc ls {target}'):
                    _, out, _ = command.assert_command(['mc', 'ls', target], 'STDOUT', put_filename)
                    self.assertIn(f'{updated_size_in_bytes}B STANDARD', out)
                    self.assertNotIn(f'{original_size_in_bytes}B STANDARD', out)

            aws_targets = [
                f's3://{self.bucket_name}/{collection_name}/{put_filename}',
                f's3://{self.bucket_name}/{collection_name}/'
            ]
            for target in aws_targets:
                with self.subTest(f'aws s3 ls {target}'):
                    # List the data object...
                    _, out, _ = command.assert_command(
                        [
                            'aws',
                            '--profile',
                            's3_api_alice',
                            '--endpoint-url',
                            self.s3_api_url,
                            's3',
                            'ls',
                            target
                        ],
                        'STDOUT',
                        put_filename)
                    self.assertIn(f'{updated_size_in_bytes} {put_filename}', out)
                    self.assertNotIn(f'{original_size_in_bytes} {put_filename}', out)

            target = f'{collection_name}/{put_filename}'
            with self.subTest(f'botocore list_objects_v2 prefix={target}'):
                listobjects_result = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix=target)
                print(listobjects_result)
                self.assertEqual(len(listobjects_result['Contents']), 1)
                self.assert_key_in_contents_list(listobjects_result, target, size=updated_size_in_bytes)

        finally:
            command.assert_command(['ils', '-Lr'], 'STDOUT') # debugging
            command.assert_command(['rm', '-f', put_filename])
            command.assert_command(['irm', '-rf', collection_path])
