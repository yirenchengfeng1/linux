#!/bin/bash
# REALITY一键安装脚本
# Author: YouTube频道<https://www.youtube.com/@aifenxiangdexiaoqie>

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'


colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

Xray() {
    clear
    bash -c "$(curl -s -L https://raw.githubusercontent.com/yirenchengfeng1/linux/main/reality_xray.sh)"
}

Singbox() {
    clear
    bash -c "$(curl -s -L https://raw.githubusercontent.com/yirenchengfeng1/linux/main/reality_singbox.sh)"
}


menu() {
    clear
    echo "##################################################################"
    echo -e "#                   ${RED}Reality一键安装脚本${PLAIN}                                    #"
    echo -e "# ${GREEN}作者${PLAIN}: 爱分享的小企鹅                                                     #"
    echo -e "# ${GREEN}网址${PLAIN}: hhttp://www.youtube.com/@aifenxiangdexiaoqie                       #"
	echo -e "# ${GREEN}VPS选购攻略${PLAIN}：https://lovetoshare.top/archives/3.html                     #"
	echo -e "# ${GREEN}年付10美金VPS推荐${PLAIN}：https://my.racknerd.com/aff.php?aff=9734&pid=838      #"	
    echo "##################################################################"

    echo -e "  ${GREEN}  <请选择内核版本！>  ${YELLOW}"	
    echo -e "  ${GREEN}1.${PLAIN}  Xray版"
    echo -e "  ${GREEN}2.${PLAIN}  Singbox版"
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN}   退出"
    echo 

    read -p " 请选择操作[0-2]：" answer
    case $answer in
        0)
            exit 0
            ;;
        1)
            Xray
            ;;
        2)
	        Singbox
            ;;
        *)
            echo " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

menu
