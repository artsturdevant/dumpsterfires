import asyncio
import json
import logging
import os
import pprint
import time

import boto3


class AWSExpo:

    def _enable_mfa(self, **kwargs):

        totp_token = input('Enter the TOTP code: ')
        session_duration_seconds = kwargs.get('session_duration_seconds', 900)
        mfa_serial = kwargs.get('mfa_serial', None)
        sts = boto3.client(
            'sts',
            aws_access_key_id=kwargs.get('secret', None),
            aws_secret_access_key=kwargs.get('key', None)
        )

        try:
            credential_response = sts.get_session_token(
                DurationSeconds=session_duration_seconds,
                SerialNumber=mfa_serial,
                TokenCode=totp_token
            )

            return {
                'secret': credential_response['Credentials'].get('AccessKeyId', None),
                'key': credential_response['Credentials'].get('SecretAccessKey', None),
                'token': credential_response['Credentials'].get('SessionToken', None)
            }
        except Exception as e:
            logging.critical('Could not authenticate to AWS. Error: {}'.format(e))
            raise e

    def _aws_cred_dance(self, **kwargs):
        """
        THis method is responsible for taking in a credential pair and returning a formatted dict
        Args:
            **kwargs:
                secret      (str): AWS API Secret
                key         (str): AWS API Secret Key
                mfa         (bool): True if MFA is enabled, otherwise False
                mfa_serial  (str): If provided, is a string ARN of the users MFA device in AWS
        Returns:
            dict
        """

        secret_dict = {
            'secret': None,
            'key': None
        }

        if not kwargs.get('secret', None) or not kwargs.get('key', None):
            # returns an empty dict if no credentials are given
            return secret_dict

        # If MFA isn't enabled or the serial isn't given - use the provided creds.
        if not kwargs.get('mfa', None) or not kwargs.get('mfa_serial', None):
            secret_dict['secret'] = kwargs.get('secret', None)
            secret_dict['key'] = kwargs.get('key', None)

            return secret_dict

        if kwargs.get('mfa', None):
            return self._enable_mfa(
                mfa_serial=kwargs.get('mfa_serial', None),
                secret=kwargs.get('secret', None),
                key=kwargs.get('key', None)
            )

        return {}

    def __init__(self, **kwargs):
        """
        Args:
            **kwargs:
                mfa_enabled (bool): Determines
                mfa_serial (str): The ARN to the user MFA device
                aws_secret (str): The AWS API Secret i.e. The API user id
                aws_secret_key (str): The AWS API Secret Key i.e. The API password
        """
        # TODO: Enable AWS profiles to hold credentials

        mfa_enabled = kwargs.get('mfa_enabled', bool(os.getenv('MFA_ENABLED', False)))
        mfa_serial = kwargs.get('mfa_serial', os.getenv('AWS_MFA_DEVICE', None))

        self.clients = [
            'ec2',
            'ecs',
            'rds'
        ]

        provided_aws_secret = kwargs.get('aws_secret', os.getenv('AWS_ACCESS_KEY_ID', None))
        provided_aws_secret_key = kwargs.get('aws_secret_key', os.getenv('AWS_SECRET_ACCESS_KEY', None))

        creds = self._aws_cred_dance(
            secret=provided_aws_secret,
            key=provided_aws_secret_key,
            mfa=mfa_enabled,
            mfa_serial=mfa_serial
        )

        self.session = boto3.Session(
            aws_access_key_id=creds.get('secret', None),
            aws_secret_access_key=creds.get('key', None),
            aws_session_token=creds.get('token', None)
        )

    def get_regions(self):

        response = []

        try:
            client = self.session
            response = client.get_available_regions('ec2')
        except Exception as e:
            logging.critical('Could not create session to get regions. Error: {}'.format(e))
            raise e
        finally:
            return response

    def get_all_public_addresses(self):
        """
        Args:
            **kwargs:
                ipv4 (bool): Return IPv4 public addresses. Defaults to True.
                ipv6 (bool) Return IPv6 public addresses. Defaults to False.
        Returns:
            dict: { 'ipv4' [{'instance_id': [...] }], 'ipv6': [{'instance_id': [...]}] }
        """

        filters = [
            {
                'Name': 'public-ip',
                'Values': '*'
            }
        ]

        client = self.session

        print(
            json.dumps(
                client.client('ec2', region_name='us-west-2').describe_addresses().get('Addresses', None),
                indent=4
            )
        )

    def get_ec2_instances(self, **kwargs):
        # TODO: This could be an async call

        client = self.session
        region_list = kwargs.get('region_list', self.get_regions())
        instances = []


        for region in region_list:
            ec2_ifaces = client.resource('ec2', region_name=region)
            interfaces = []

            for interface in ec2_ifaces.network_interfaces.all():
                for address in interface.private_ip_addresses:

                    if address.get('Association', {}).get('PublicIp', {}):
                        interfaces.append(address.get('Association', {}).get('PublicIp', {}))

            if interfaces:
                instances.append({
                    'region': region,
                    'interfaces': interfaces
                }
                )

        return instances

    def get_rds_instances(self, region_list=[]):

        client = self.session
        instances = []

        for region in region_list:
            rds = client.client('rds', region_name=region)

            instances.append(
                rds.describe_db_instances().get('DBInstances', [])
            )

        pprint.pprint(instances)

        return True

    def get_ecs_instances(self, region_list=[]):

        client = self.session

        tasks = []

        for region in region_list:
            ecs = client.client('ecs', region_name=region)

            for cluster in ecs.list_clusters().get('clusterArns'):

                task_list = ecs.list_tasks(cluster=cluster, maxResults=100).get('taskArns', [])

                if task_list:
                    tasks.append(
                        ecs.describe_tasks(cluster=cluster, tasks=task_list).get('tasks', [])
                    )

        return tasks

    def get_elbv2_instances(self, region_list):

        client = self.session
        elbs = []

        for region in region_list:
            elb = client.client('elbv2', region_name=region)

            elbs.append(
                elb.describe_load_balancers().get('LoadBalancers', [])
            )

        return elbs

    def get_elbv1_instances(self, region_list):

        client = self.session
        elbs = []

        for region in region_list:
            elb = client.client('elb', region_name=region)

            elbs.append(
                elb.describe_load_balancers().get('LoadBalancers', [])
            )

        return elbs


if __name__ == "__main__":
    a = AWSExpo()

    regions = a.get_regions()

    t = time.time()

    pprint.pprint(a.get_ec2_instances(region_list=regions))
    #pprint.pprint(a.get_rds_instances(region_list=regions))
    #pprint.pprint(a.get_ecs_instances(region_list=regions))
    #pprint.pprint(a.get_elbv1_instances(region_list=regions))
    #pprint.pprint(a.get_elbv2_instances(region_list=regions))
    #pprint.pprint(a.get_elbv2_instances(region_list=regions))

    rtime = time.time() - t

    print('run time (in seconds): {}'.format(rtime))