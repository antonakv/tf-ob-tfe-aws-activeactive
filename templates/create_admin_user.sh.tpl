#!/usr/bin/env bash
INITIAL_TOKEN=$(replicated admin --tty=0 retrieve-iact)

ADMIN_USERNAME="${tfe_admin_username}";
ADMIN_PASSWORD="${tfe_admin_password}";
ADMIN_EMAIL="${tfe_admin_email}"
TFE_HOSTNAME="${tfe_hostname}"
ADMIN_POST_DATA=$(cat <<EOF
{
  "username": "${ADMIN_USERNAME}",
  "email": "${ADMIN_EMAIL}",
  "password": "${ADMIN_PASSWORD}"
}
EOF
);

ADMIN_TOKEN_RESPONSE=$(curl -sSLk \
  --request POST \
  -H "Content-Type: application/json" \
  --data "${ADMIN_POST_DATA}" \
  https:///${TFE_HOSTNAME}/admin/initial-admin-user?token=${INITIAL_TOKEN} \
  | jq '.'
);
export ADMIN_TOKEN=$(echo "${ADMIN_TOKEN_RESPONSE}" | jq '.token' | tr -d '"');
echo "${ADMIN_TOKEN}"
