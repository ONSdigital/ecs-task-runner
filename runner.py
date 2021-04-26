#!/usr/bin/env python3

# -----------------------------------------------------------
# ECS Task Trigger
#
# This script is designed to run either locally or within a CI/CD system.
#
# It triggers a single task to run inside AWS ECS, using the Fargate engine, and then continues to monitor that task
# until it stops. Whilst running that task's logs will be streamed and output by the script.
#
# All inputs are passed via environment variables
#   Required:
#     - CLUSTER: The short name or full Amazon Resource Name (ARN) of the cluster on which to run your task.
#     - TASK_DEFINITION: The family and revision (family:revision ) or full ARN of the task definition to run.
#     - SUBNETS: Comma separated IDs of the subnets associated with the task or service. Limit: 16
#                   e.g. 'subnet-2299fd4b,subnet-9ca056d0,subnet-5340e029'
#     - SECURITY_GROUPS: Comma separated IDs of the security groups associated with the task or service. Limit: 5
#                   e.g. 'sg-4f97de25,sg-01b7f38dc1ef5d7cc'
#     - PUBLIC_IP: Whether the task's elastic network interface receives a public IP address.
#   Optional:
#     - AWS_ROLE: The ARN of a role to assume whilst triggering the task
#
# This script:
#     1 - Sense Checks the Inputs
#     2 - Sets up the boto3 client & session
#     3 - Sense checks the Task definition
#     4 - Creates & starts the task
#     5 - Waits for the task to be running
#     6 - The continuously
#         - Returns any new logs entries
#         - Checks the state of the task
#
#
#
# (C) 2021 Neil Smith
# MIT License
# https://github.com/nsmithuk
#
# -----------------------------------------------------------
import os
import boto3
import boto3.session
from boto3 import Session
from botocore.session import get_session
from botocore.credentials import RefreshableCredentials
import botocore
import logging
import time
import colorama
from colorama import Fore
from datetime import datetime
from pprint import pprint

# --------------------------------
# Init

colorama.init(autoreset=True)

logging.basicConfig(format=Fore.YELLOW + '%(asctime)s - %(message)s', level=logging.INFO)
logger = logging.getLogger()


# --------------------------------
# Sense Check Inputs

# The short name or full Amazon Resource Name (ARN) of the cluster on which to run your task.
cluster_id = os.environ.get('CLUSTER')
if cluster_id is None:
    logger.critical("Missing CLUSTER")
    exit(100)

# The family and revision (family:revision ) or full ARN of the task definition to run.
# If a revision is not specified, the latest ACTIVE revision is used.
task_definition_name = os.environ.get('TASK_DEFINITION')
if task_definition_name is None:
    logger.critical("Missing TASK_DEFINITION")
    exit(101)

# The IDs of the subnets associated with the task or service. There is a limit of 16 subnets
subnets = os.environ.get('SUBNETS')
if subnets is None:
    logger.critical("Missing SUBNETS")
    exit(102)

# The IDs of the security groups associated with the task or service. There is a limit of 5 security groups
security_groups = os.environ.get('SECURITY_GROUPS')
if security_groups is None:
    logger.critical("Missing SECURITY_GROUPS")
    exit(103)

# Whether the task's elastic network interface receives a public IP address.
public_ip = os.environ.get('PUBLIC_IP', 'DISABLED')
if public_ip not in ['DISABLED', 'ENABLED']:
    logger.critical("Invalid PUBLIC_IP")
    exit(104)


# --------------------------------
# Setup the boto3 client & session

if 'AWS_ROLE' in os.environ:
    def _refresh():
        params = {
            "RoleArn": os.environ['AWS_ROLE'],
            "DurationSeconds": 60 * 20,
            "RoleSessionName": "ecs-task",
        }
        response = boto3.client('sts').assume_role(**params).get("Credentials")
        credentials = {
            "access_key": response.get("AccessKeyId"),
            "secret_key": response.get("SecretAccessKey"),
            "token": response.get("SessionToken"),
            "expiry_time": response.get("Expiration").isoformat(),
        }
        logger.info(Fore.GREEN + 'Refreshing credentials. Expires: %s' % response.get("Expiration").isoformat())
        return credentials

    session_credentials = RefreshableCredentials.create_from_metadata(
        metadata=_refresh(),
        refresh_using=_refresh,
        method="sts-assume-role",
    )

    session = get_session()
    session._credentials = session_credentials
    autorefresh_session = Session(botocore_session=session)

    ecs_client = autorefresh_session.client('ecs')
    log_client = autorefresh_session.client('logs')
else:
    ecs_client = boto3.client('ecs')
    log_client = boto3.client('logs')


# --------------------------------
# Sense check the Task definition

logger.info("Checking the task definition...")
task_definition = ecs_client.describe_task_definition(
    taskDefinition=task_definition_name,
)

# The above throws an exception if the task definition cannot be found, so won't check any further here

containers = []

for container in task_definition['taskDefinition']['containerDefinitions']:
    containers.append({
        'name': container['name'],
        'log_group': container['logConfiguration']['options']['awslogs-group'],
        'log_prefix': container['logConfiguration']['options']['awslogs-stream-prefix']
    })

if len(containers) < 1:
    logger.critical(Fore.RED + 'We need at least one container to continue')
    exit(1)

if len(containers) > 4:
    logger.critical(Fore.RED + 'Only up to four containers is currently supported')
    exit(1)

logger.info("Using the following containers: %s" % containers)


# --------------------------------
# Create & start the task

logger.info("Creating the task...")
task = ecs_client.run_task(
    cluster=cluster_id,
    taskDefinition=task_definition_name,
    launchType='FARGATE',
    networkConfiguration={
        'awsvpcConfiguration': {
            'subnets': subnets.split(','),
            'securityGroups': security_groups.split(','),
            'assignPublicIp': public_ip
        }
    }
)

try:
    task_arn = task['tasks'][0]['taskArn']
except KeyError as e:
    logger.critical(Fore.RED + 'Error starting task: %s' % e)
    exit(1)

log_stream_postfix = task_arn.rsplit('/', 1)[1]

logger.info("Task arn: %s" % task_arn)
logger.info("Log stream ID: %s" % log_stream_postfix)


# --------------------------------
# Wait for the task to be running

waiter = ecs_client.get_waiter('tasks_running')

try:
    logger.info("Waiting for task to reach a state of 'running'...")
    waiter.wait(
        cluster=cluster_id,
        tasks=[task_arn],
    )
except botocore.exceptions.WaiterError as e:
    logger.critical(Fore.RED + 'Task appears to have failed to start')
    exit(1)

logger.info("Task is running")


# --------------------------------
# Init the ongoing monitoring of the task

# Each container is given a different colour to help distinguish
text_colours = [Fore.WHITE, Fore.CYAN, Fore.BLUE, Fore.GREEN]

# Track the number of continuous exceptions we've seen
exceptions = 0

# Tracks which log stream we saw last, allowing us to add formatting between separate streams
last_seen_logs_were_from_idx = -1

# Continue checking; we'll explicitly exit when the task has stopped
while True:
    # Avoid rate limiting
    time.sleep(1 + len(containers))

    try:
        # --------------------------------
        # Return any new logs since we last checked

        for idx, container in enumerate(containers):

            stream_id = "%s/%s/%s" % (container['log_prefix'], container['name'], log_stream_postfix)
            nextToken = container.get('next_token', 'f/0')  # 'f/0' comes from AWS; it means 'from the start'.

            logger.debug("Getting stream: %s" % stream_id)
            logger.debug("Token: %s" % nextToken)

            logs = log_client.get_log_events(
                logGroupName=container['log_group'],
                logStreamName=stream_id,
                nextToken=nextToken,
                startFromHead=True
            )

            if len(logs['events']) > 0:
                if last_seen_logs_were_from_idx != idx:
                    print(text_colours[idx] + "\nLogs from %s\n-" % stream_id)
                    last_seen_logs_were_from_idx = idx

                for event in logs['events']:
                    date = datetime.fromtimestamp(event['timestamp']/1000.0)
                    print(text_colours[idx] + "%s - %s" % (date, event['message']))

            containers[idx]['next_token'] = logs['nextForwardToken']

        # --------------------------------
        # Check the state of the task

        tasks = ecs_client.describe_tasks(
            cluster=cluster_id,
            tasks=[task_arn],
        )

        task_state = tasks['tasks'][0]['lastStatus']
        logger.debug("Task state: %s" % task_state)

        # Reset this
        exceptions = 0

        if task_state == 'STOPPED':
            logger.info("Task has stopped")

            pprint(tasks)

            none_zero_exit_code = False
            for container in tasks['tasks'][0]['containers']:
                if container['exitCode'] != 0:
                    none_zero_exit_code = True

            if none_zero_exit_code:
                logger.error(Fore.RED + "The task completed with errors")
                for container in tasks['tasks'][0]['containers']:
                    logger.error(Fore.RED + "%s exited with code %d" % (container['name'], container['exitCode']))
                exit(1)
            else:
                logger.info(Fore.GREEN + "Task has completed successfully")
                exit(0)

    except botocore.exceptions.ClientError as e:
        logger.warning(
            Fore.RED + "Non-terminal exception seen whilst checking logs (%s). The request will be retried." % e)

        if exceptions >= 100:
            logger.critical("Too many exceptions; exiting.")
            exit(1)

        exceptions = exceptions + 1
