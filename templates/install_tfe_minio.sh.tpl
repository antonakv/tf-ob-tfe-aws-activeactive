#!/usr/bin/env bash
mkdir -p /home/ubuntu/install

mkdir -p /home/ubuntu/.aws

echo "
{
    \"aws_access_key_id\": {
        \"value\": \"${minio_access_key}\"
    },
    \"aws_instance_profile\": {
        \"value\": \"0\"
    },
    \"aws_secret_access_key\": {
        \"value\": \"${minio_secret_key}\"
    },
    \"azure_account_key\": {},
    \"azure_account_name\": {},
    \"azure_container\": {},
    \"azure_endpoint\": {},
    \"backup_token\": {
        \"value\": \"3e69c0572c1eddf7f232cf60f6b8634194bf40d09aa9535c78430e64df407ec4\"
    },
    \"ca_certs\": {},
    \"capacity_concurrency\": {
        \"value\": \"10\"
    },
    \"capacity_memory\": {
        \"value\": \"512\"
    },
    \"custom_image_tag\": {
        \"value\": \"hashicorp/build-worker:now\"
    },
    \"disk_path\": {},
    \"enable_active_active\": {
        \"value\": \"0\"
    },
    \"enable_metrics_collection\": {
        \"value\": \"1\"
    },
    \"enc_password\": {
        \"value\": \"${enc_password}\"
    },
    \"extern_vault_addr\": {},
    \"extern_vault_enable\": {
        \"value\": \"0\"
    },
    \"extern_vault_path\": {},
    \"extern_vault_propagate\": {},
    \"extern_vault_role_id\": {},
    \"extern_vault_secret_id\": {},
    \"extern_vault_token_renew\": {},
    \"extra_no_proxy\": {},
    \"force_tls\": {
        \"value\": \"0\"
    },
    \"gcs_bucket\": {},
    \"gcs_credentials\": {
        \"value\": \"{}\"
    },
    \"gcs_project\": {},
    \"hairpin_addressing\": {
        \"value\": \"0\"
    },
    \"hostname\": {
        \"value\": \"${hostname}\"
    },
    \"iact_subnet_list\": {},
    \"iact_subnet_time_limit\": {
        \"value\": \"60\"
    },
    \"installation_type\": {
        \"value\": \"production\"
    },
    \"pg_dbname\": {
        \"value\": \"mydbtfe\"
    },
    \"pg_extra_params\": {
        \"value\": \"sslmode=disable\"
    },
    \"pg_netloc\": {
        \"value\": \"${pgsqlhostname}\"
    },
    \"pg_password\": {
        \"value\": \"${pgsqlpassword}\"
    },
    \"pg_user\": {
        \"value\": \"${pguser}\"
    },
    \"placement\": {
        \"value\": \"placement_s3\"
    },
    \"production_type\": {
        \"value\": \"external\"
    },
    \"redis_host\": {},
    \"redis_pass\": {
        \"value\": \"NGVITSiZJKkmtC9ed1XWjScsVZMnXJx5\"
    },
    \"redis_port\": {},
    \"redis_use_password_auth\": {},
    \"redis_use_tls\": {},
    \"restrict_worker_metadata_access\": {
        \"value\": \"0\"
    },
    \"s3_bucket\": {
        \"value\": \"${s3bucket}\"
    },
    \"s3_endpoint\": {
        \"value\": \"${s3endpoint}\"
    },
    \"s3_region\": {
        \"value\": \"${s3region}\"
    },
    \"s3_sse\": {},
    \"s3_sse_kms_key_id\": {},
    \"tbw_image\": {
        \"value\": \"default_image\"
    },
    \"tls_ciphers\": {},
    \"tls_vers\": {
        \"value\": \"tls_1_2_tls_1_3\"
    }
}
" > /home/ubuntu/install/settings.json

echo "
{
    \"DaemonAuthenticationType\":     \"password\",
    \"DaemonAuthenticationPassword\": \"Password1#\",
    \"TlsBootstrapType\":             \"server-path\",
    \"TlsBootstrapHostname\":         \"${hostname}\",
    \"ReleaseSequence\":         ${release_sequence},
    \"TlsBootstrapCert\":             \"/home/ubuntu/install/server.crt\",
    \"TlsBootstrapKey\":              \"/home/ubuntu/install/server.key\",
    \"BypassPreflightChecks\":        true,
    \"ImportSettingsFrom\":           \"/home/ubuntu/install/settings.json\",
    \"LicenseFileLocation\":          \"/home/ubuntu/install/license.rli\"
}" > /home/ubuntu/install/replicated.conf
echo "${cert_pem}" > /home/ubuntu/install/server.crt
echo "${key_pem}" > /home/ubuntu/install/server.key
IPADDR=$(hostname -I | awk '{print $1}')
echo "#!/usr/bin/env bash
chmod 600 /home/ubuntu/install/server.key
cd /home/ubuntu/install
aws s3 cp s3://aakulov-aws10-tfe-tfe . --recursive
curl -# -o /home/ubuntu/install/install.sh https://install.terraform.io/ptfe/stable
chmod +x install.sh
sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
cp /home/ubuntu/install/replicated.conf /etc/replicated.conf
cp /home/ubuntu/install/replicated.conf /root/replicated.conf
chown -R ubuntu: /home/ubuntu/install

aws configure set aws_access_key_id ${minio_access_key}
aws configure set aws_secret_access_key ${minio_secret_key}

aws s3api create-bucket --acl private --bucket ${s3bucket}  --endpoint-url ${s3endpoint}
aws s3 ls s3://${s3bucket}  --endpoint-url ${s3endpoint}

yes | sudo /usr/bin/bash /home/ubuntu/install/install.sh no-proxy private-address=$IPADDR public-address=$IPADDR
exit 0
" > /home/ubuntu/install/install_tfe.sh

echo "#!/usr/bin/env bash
  set -x
  date
  # health check until app becomes ready
  while ! curl -ksfS --connect-timeout 5 \"https://$IPADDR/_health_check\"; do
    sleep 5
  done
  date
  sudo /usr/bin/bash /home/ubuntu/install/create_admin_user.sh > /home/ubuntu/install/admin_token.txt
  date
" > /home/ubuntu/install/healthcheck.sh

echo "#!/usr/bin/env bash
while ! INITIAL_TOKEN=$(replicated admin --tty=0 retrieve-iact); do
  sleep 5
done

ADMIN_POST_DATA=$(cat <<EOF
{
  \"username\": \"${tfe_admin_username}\",
  \"email\": \"${tfe_admin_email}\",
  \"password\": \"${tfe_admin_password}\"
}
EOF
);

ADMIN_TOKEN_RESPONSE=$(curl -sSLk \
  --request POST \
  -H \"Content-Type: application/json\" \
  --data $ADMIN_POST_DATA \
  https:///${tfe_hostname}/admin/initial-admin-user?token=$INITIAL_TOKEN \
  | jq '.'
);

export ADMIN_TOKEN=$(echo \"$ADMIN_TOKEN_RESPONSE\" | jq '.token' | tr -d '\"');
echo \"$ADMIN_TOKEN\"
" > /home/ubuntu/install/create_admin_user.sh

echo "{
  \"debug\": true
}
" > /home/ubuntu/install/daemon.json 

sudo cp /home/ubuntu/install/daemon.json /etc/docker/deamon.json

chmod +x /home/ubuntu/install/install_tfe.sh
chmod +x /home/ubuntu/install/healthcheck.sh

sh /home/ubuntu/install/healthcheck.sh &> /home/ubuntu/install/hc_tfe.log &

sh /home/ubuntu/install/install_tfe.sh &> /home/ubuntu/install/install_tfe.log
