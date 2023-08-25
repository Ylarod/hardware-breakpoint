#!/bin/sh
###
 # @Author: zwf 240970521@qq.com
 # @Date: 2023-08-25 21:21:01
 # @LastEditors: zwf 240970521@qq.com
 # @LastEditTime: 2023-08-25 21:27:58
 # @FilePath: /hardware-breakpoint/make.sh
 # @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
### 
KERNEL_DIR=/home/zwf/x3_src/kernel
hotbot_key=$KERNEL_DIR/certs/hobot_fixed_signing_key.pem
sign_key=$KERNEL_DIR/certs/signing_key.x509
sign_tools=$KERNEL_DIR/scripts/sign-file

rm -rf .vscode/compile_commands.json
make clean
bear make
mv compile_commands.json .vscode/compile_commands.json

#给驱动加签名
$sign_tools sha512 $hotbot_key $sign_key ./hw_break.ko

#copy到nfs目录
cp ./hw_break.ko ~/x3sdb/nfs/
