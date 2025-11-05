#! /bin/bash

# Several requests to issue to a running resty container

BOUND_PORT="${1:-8111}"

echo ""
echo "========================="
echo "Item and inner list tests - progress though value types with and without params"
echo "========================="
echo ""

printf "\n\n*** Test boolean true ***\n"
curl -D- -H "sfv:?1;param=123" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test boolean false ***\n"
curl -D- -H "sfv:?1" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test integer 45 ***\n"
curl -D- -H "sfv:45;param1;param2=\"my string\"" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test decimal 45.1 ***\n"
curl -D- -H "sfv:45.1;param1=%\"my %c3%96 string\"" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test date 1744045540 ***\n"
curl -D- -H "sfv:@1744045540" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test string ***\n"
curl -D- -H "sfv:\"a string like no other\";param1;param2;param3" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test token 1 ***\n"
curl -D- -H "sfv:*big/\$good_token#!;param1=@1744045540" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test token 2 ***\n"
curl -D- -H "sfv:Big/%good_token&'*-;param1=5540" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test token 3 ***\n"
curl -D- -H "sfv:big+/good.token^\`|~:;param1=5540.113" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test display string ***\n"
curl -D- -H "sfv:%\"my %c3%96 string\";param1=token/string" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test byte sequence ***\n"
curl -D- -H "sfv::DeviceIDDeviceIDDevicQ==:;param1=:DeviceIODeviceIODevicQ==:" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test inner list 1 ***\n"
curl -D- -H "sfv:(:DeviceIDDeviceIDDevicQ==: @1744045540 Big/%good_token&'*-)" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test inner list 2 ***\n"
curl -D- -H "sfv:(:YQ==: @1744045540 Big/%good_token&'*-);param1=5540.113;param2=:DeviceIODeviceIODevicQ==:" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test inner list 3 - entries with different types ***\n"
curl -D- -H "sfv:(?0 ?1 123 134.321 @1744045540 \"something\" Big/%good_token&'*- %\"my %c3%96 string\" :YQ==:)" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test inner list 4 - multiple entries with params ***\n"
curl -D- -H "sfv:(?0;p2=?0;p3=123;p4=123.456 ?1;date=@1000 123;str=\"attention\");p45=Big/%good_token&'*-" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test inner list 5 - multiple entries with more params ***\n"
curl -D- -H "sfv:(134.321;str=%\"my %c3%96 string\" @1744045540;boolt;boolf=?0 \"something\";n=0.1 Big/%good_token&'*-;mybytes=:JQ==:)" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test inner list 6 - multiple entries with even more params ***\n"
curl -D- -H "sfv:(%\"my %c3%96 string\";p4=123.4;p3=123 :YQ==:;t1=token ?0 ?1 123 134.321 @1744045540;bool1);bool2=?0" -H "sfvt:ITEM" http://0.0.0.0:${BOUND_PORT}/sfv_test

echo ""
echo "================"
echo "Outer list tests - progress though value types with and without params"
echo "================"
echo ""

printf "\n\n*** Test outer list 1 - single entry list (the empty list causes curl or nginx to ignore the header) ***\n"
curl -D- -H "sfv:?0" -H "sfvt:LIST" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test outer list 2 - single empty inner list ***\n"
curl -D- -H "sfv:()" -H "sfvt:LIST" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test outer list 3 - entries with different types ***\n"
curl -D- -H "sfv:?0, ?1, 123, 134.321, @1744045540, \"something\", Big/%good_token&'*-, %\"my %c3%96 string\", :YQ==:, ()" -H "sfvt:LIST" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test outer list 4 - multiple entries with params ***\n"
curl -D- -H "sfv:(tok1);p1, ?0;p2=?0;p3=123;p4=123.456, ?1;date=@1000, 123;str=\"attention\";p45=Big/%good_token&'*-" -H "sfvt:LIST" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test outer list 5 - multiple entries with more params ***\n"
curl -D- -H "sfv:134.321;str=%\"my %c3%96 string\", @1744045540;boolt;boolf=?0, \"something\";n=0.1, Big/%good_token&'*-;mybytes=:JQ==:" -H "sfvt:LIST" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test outer list 6 - multiple entries with even more params ***\n"
curl -D- -H "sfv:%\"my %c3%96 string\";p4=123.4;p3=123, :YQ==:;t1=token, (?0 ?1 123 134.321 @1744045540);bool1;bool2=?0" -H "sfvt:LIST" http://0.0.0.0:${BOUND_PORT}/sfv_test


echo ""
echo "================"
echo "Dictionary tests - progress though value types with an without params"
echo "================"
echo ""

printf "\n\n*** Test dictionary 1  ***\n"
curl -D- -H "sfv:k1=(@1744045540 12 tok);param1, k2=\"my string\";bool1, k3=?0, k4;tok2" -H "sfvt:DICTIONARY" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test dictionary 2 - entries with different types ***\n"
curl -D- -H "sfv:k1=?0, k2, k3=123, k4=134.321, k5=@1744045540, k6=\"something\", k7=Big/%good_token&'*-, k8=%\"my %c3%96 string\", k9=:YQ==:, k10=()" -H "sfvt:DICTIONARY" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test dictionary 3 - multiple entries with params ***\n"
curl -D- -H "sfv:k1=(tok1);p1, k2=?0;p2=?0;p3=123;p4=123.456, k3;date=@1000, k4=123;str=\"attention\";p45=Big/%good_token&'*-" -H "sfvt:DICTIONARY" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test dictionary 4 - multiple entries with more params ***\n"
curl -D- -H "sfv:k1=134.321;str=%\"my %c3%96 string\", k2=@1744045540;boolt;boolf=?0, k3=\"something\";n=0.1, k4=Big/%good_token&'*-;mybytes=:JQ==:" -H "sfvt:DICTIONARY" http://0.0.0.0:${BOUND_PORT}/sfv_test

printf "\n\n*** Test dictionary 5 - multiple entries with even more params ***\n"
curl -D- -H "sfv:k1=%\"my %c3%96 string\";p4=123.4;p3=123, k2=:YQ==:;t1=token, k3=(?0 ?1 123 134.321 @1744045540);bool1;bool2=?0" -H "sfvt:DICTIONARY" http://0.0.0.0:${BOUND_PORT}/sfv_test
