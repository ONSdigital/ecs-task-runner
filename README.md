# AWS ECS Task Runner

A simple-ish script that triggers a single AWS ECS task and then continues to monitor that task until it terminates. 
Whilst running, the task's logs will be streamed and output by the script.

This script is designed to run locally or within a CI/CD system.

## Usage

All inputs are passed via environment variables.

### Required
- **CLUSTER**: The short name or full Amazon Resource Name (ARN) of the cluster on which to run your task.
- **TASK_DEFINITION**: The family and revision (family:revision ) or full ARN of the task definition to run.
- **SUBNETS**: Comma separated IDs of the subnets associated with the task or service. Limit: 16. e.g. 'subnet-2299fd4b,subnet-9ca056d0,subnet-5340e029'
- **SECURITY_GROUPS**: Comma separated IDs of the security groups associated with the task or service. Limit: 5. e.g. 'sg-4f97de25,sg-01b7f38dc1ef5d7cc'
- **PUBLIC_IP**: Whether the task's elastic network interface receives a public IP address. Either `DISABLED` or `ENABLED`. Defaults to `DISABLED`.
### Optional
- **AWS_ROLE**: The ARN of a role to assume whilst triggering the task

## Example
To trigger a task
```shell
docker run -it --rm \
-e AWS_ACCESS_KEY_ID \
-e AWS_SECRET_ACCESS_KEY \
-e AWS_DEFAULT_REGION="eu-west-2" \
-e CLUSTER="arn:aws:ecs:eu-west-2:123456789876:cluster/Testing" \
-e TASK_DEFINITION="hello-world:1" \
-e SUBNETS="subnet-2299fd4b,subnet-9ca056d0,subnet-5340e029" \
-e SECURITY_GROUPS="sg-4f97de25,sg-01b7f38dc1ef5d7cc" \
-e AWS_ROLE="arn:aws:iam::123456789876:role/admin-role" \
-e PUBLIC_IP="ENABLED" \
onsdigital/spp-ecs-task-runner:1
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
