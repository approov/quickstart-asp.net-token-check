#! /bin/bash

# Several requests to issue to a running resty container

BOUND_PORT="${1:-8111}"

# For JWTs - construct them using https://jwt.io although for obvious reasons
# you should never copy a real secret into the website.
#
# Test secret in base64 and base64url formats for use in the jwt.io form:
# TEST+SECRET/TEST+SECRET/TEST+SECRET/TEST+SECRET/TEST+SECRET/TEST+SECRET/TEST+SECRET/AA
# TEST-SECRET_TEST-SECRET_TEST-SECRET_TEST-SECRET_TEST-SECRET_TEST-SECRET_TEST-SECRET_AA
#

# Timestamps used in test tokens:
# 1999999999 - Wed 18 May 04:33:19 BST 2033
# 1700000000 - Tue 14 Nov 22:13:20 GMT 2023
# 1710000000 - Sat  9 Mar 16:00:00 GMT 2024

# Good full token:
# Header: {
#   "alg": "HS256",
#   "typ": "JWT"
# }
# Payload: {
#   "aud": "approov.io",
#   "exp": 1999999999,
#   "iat": 1700000000,
#   "iss": "ApproovAccountID.approov.io",
#   "sub": "approov|ExampleApproovTokenDID==",
#   "ip": "1.2.3.4",
#   "did": "ExampleApproovTokenDID=="
# }
#
GOOD_FULL_TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IkFwcHJvb3ZBY2NvdW50SUQuYXBwcm9vdi5pbyIsInN1YiI6ImFwcHJvb3Z8RXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwiaXAiOiIxLjIuMy40IiwiZGlkIjoiRXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09In0.1jKWka6OrKAURvibZ26ApvOLNl6pv5cVuu2pJnExvW0'

# Good full token with token binding pay claim which requires the following header values:
# - Authorization: Bearer myauth_token
# - X-Device-Id: my-device-id
# Header: {
#   "alg": "HS256",
#   "typ": "JWT"
# }
# Payload: {
#   "aud": "approov.io",
#   "exp": 1999999999,
#   "iat": 1700000000,
#   "iss": "ApproovAccountID.approov.io",
#   "sub": "approov|ExampleApproovTokenDID==",
#   "ip": "1.2.3.4",
#   "did": "ExampleApproovTokenDID==",
#   "pay": "71tnS3rSq2lanEWrKz4MoexiOMtv7w0fspfM8BAQKNU="
# }
#
GOOD_FULL_TOKEN_WITH_BINDING='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IkFwcHJvb3ZBY2NvdW50SUQuYXBwcm9vdi5pbyIsInN1YiI6ImFwcHJvb3Z8RXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwiaXAiOiIxLjIuMy40IiwiZGlkIjoiRXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwicGF5IjoiNzF0blMzclNxMmxhbkVXckt6NE1vZXhpT010djd3MGZzcGZNOEJBUUtOVT0ifQ.M0CJoQ-cQto-8OIR_d7MaLBOixzKZeN6lmW_ot76Y0Q'

# Good minimal token:
# Header: {
#   "alg": "HS256",
#   "typ": "JWT"
# }
# Payload: {
#   "exp": 1999999999,
#   "did": "ExampleApproovTokenDID=="
# }
#
GOOD_MIN_TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5OTk5OTk5OTksImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9.1dR3xFNCWonw3Cdm3UbZRIlfL-IWy_ncnF3aA_hdDps'

BAD_TOKEN_BAD_SIG='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5OTk5OTk5OTksImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9.2dR3xFNCWonw3Cdm3UbZRIlfL-IWy_ncnF3aA_hdDps'

BAD_TOKEN_INVALID_ENCODING='eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.eyJleHAiOjE5OTk5OTk5OTksImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9.NwqfsaOUBfXaf8KxRZovYCy0c6hqy29g88z1LIgzuQY'

BAD_TOKEN_NO_EXPIRY='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJBcHByb292QWNjb3VudElELmFwcHJvb3YuaW8iLCJzdWIiOiJhcHByb292fEV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSIsImlwIjoiMS4yLjMuNCIsImRpZCI6IkV4YW1wbGVBcHByb292VG9rZW5ESUQ9PSJ9.eSOEdq__Wg4fiMHGLN2afqIsymYwH4KSamKwHM_r0OE'

BAD_TOKEN_EXPIRED='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiZXhwIjoxNzEwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IkFwcHJvb3ZBY2NvdW50SUQuYXBwcm9vdi5pbyIsInN1YiI6ImFwcHJvb3Z8RXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwiaXAiOiIxLjIuMy40IiwiZGlkIjoiRXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09In0.Mv8Y73reHTPdPsFXCqS-TC7J60Y5t1jxeojZOjli_iQ'

# signed with the correct secret but contains a mismatching token binding
BAD_TOKEN_WRONG_BINDING='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHByb292LmlvIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IkFwcHJvb3ZBY2NvdW50SUQuYXBwcm9vdi5pbyIsInN1YiI6ImFwcHJvb3Z8RXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwiaXAiOiIxLjIuMy40IiwiZGlkIjoiRXhhbXBsZUFwcHJvb3ZUb2tlbkRJRD09IiwicGF5IjoiTWlzbWF0Y2hpbmdCaW5kaW5nIn0.kriaAIhtORaMXYwgEgA8AdW_5RUcVb2NRgwVM1trrjY'

printf "\n\n*** Test good full token ***\n"
curl -D- -H "Approov-Token:${GOOD_FULL_TOKEN}" http://0.0.0.0:${BOUND_PORT}/token

printf "\n\n*** Test good minimal token ***\n"
curl -D- -H "Approov-Token:${GOOD_MIN_TOKEN}" http://0.0.0.0:${BOUND_PORT}/token

printf "\n\n*** Test good full token with binding ***\n"
curl -D- -H "Authorization:Bearer myauth_token" -H "X-Device-Id: my-device-id" -H "Approov-Token:${GOOD_FULL_TOKEN_WITH_BINDING}" http://0.0.0.0:${BOUND_PORT}/token_binding

printf "\n\n*** Test bad token - bad signature ***\n"
curl -D- -H "Authorization:Bearer myauth_token" -H "X-Device-Id: my-device-id" -H "Approov-Token:${BAD_TOKEN_BAD_SIG}" http://0.0.0.0:${BOUND_PORT}/token

printf "\n\n*** Test bad token - invalid encoding ***\n"
curl -D- -H "Approov-Token:${BAD_TOKEN_INVALID_ENCODING}" http://0.0.0.0:${BOUND_PORT}/token

printf "\n\n*** Test bad token - no expiry ***\n"
curl -D- -H "Approov-Token:${BAD_TOKEN_NO_EXPIRY}" http://0.0.0.0:${BOUND_PORT}/token

printf "\n\n*** Test bad token - expired ***\n"
curl -D- -H "Approov-Token:${BAD_TOKEN_EXPIRED}" http://0.0.0.0:${BOUND_PORT}/token

printf "\n\n*** Test missing binding with good full token ***\n"
curl -D- -H "Authorization:Bearer myauth_token" -H "X-Device-Id: my-device-id" -H "Approov-Token:${GOOD_FULL_TOKEN}" http://0.0.0.0:${BOUND_PORT}/token_binding

printf "\n\n*** Test missing authorization with valid token binding token ***\n"
curl -D- -H "X-Device-Id: my-device-id" -H "Approov-Token:${GOOD_FULL_TOKEN_WITH_BINDING}" http://0.0.0.0:${BOUND_PORT}/token_binding

printf "\n\n*** Test bad token - correctly signed but with the wrong binding ***\n"
curl -D- -H "Authorization:Bearer myauth_token" -H "X-Device-Id: my-device-id" -H "Approov-Token:${BAD_TOKEN_WRONG_BINDING}" http://0.0.0.0:${BOUND_PORT}/token_binding
