#!/bin/bash
mkdir /srv/gitlab
export GITLAB_HOME=/srv/gitlab
docker run --detach \
  --hostname git.laboratory.htb \
  --publish 60443:443 --publish 60080:80 --publish 60022:22 \
  --name gitlab \
  --restart always \
  --volume $GITLAB_HOME/config:/etc/gitlab \
  --volume $GITLAB_HOME/logs:/var/log/gitlab \
  --volume $GITLAB_HOME/data:/var/opt/gitlab \
  gitlab/gitlab-ce:latest