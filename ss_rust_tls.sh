#!/bin/bash
# shadowsocks/ss_rust一键安装脚本
# Author: 爱分享的小企鹅


RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

BASE=`pwd`
OS=`hostnamectl | grep -i system | cut -d: -f2`

NAME="shadowsocks-rust"
CONFIG_FILE="/etc/${NAME}/config.json"
SERVICE_FILE="/etc/systemd/system/${NAME}.service"

V6_PROXY=""
IP=`curl -sL -4 ip.sb`
if [[ "$?" != "0" ]]; then
    IP=`curl -sL -6 ip.sb`
    V6_PROXY="https://gh.hijk.art/"
fi

colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

checkSystem() {
    result=$(id | awk '{print $1}')
    if [[ $result != "uid=0(root)" ]]; then
        colorEcho $RED " 请以root身份执行该脚本"
        exit 1
    fi

    res=`which yum 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        res=`which apt 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorEcho $RED " 不受支持的Linux系统"
            exit 1
        fi
        PMT="apt"
        CMD_INSTALL="apt install -y "
        CMD_REMOVE="apt remove -y "
        CMD_UPGRADE="apt update; apt upgrade -y; apt autoremove -y"
    else
        PMT="yum"
        CMD_INSTALL="yum install -y "
        CMD_REMOVE="yum remove -y "
        CMD_UPGRADE="yum update -y"
    fi
    res=`which systemctl 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        colorEcho $RED " 系统版本过低，请升级到最新版本"
        exit 1
    fi
}

status() {
    export PATH=/usr/local/bin:$PATH
    cmd="$(command -v ssserver)"
    if [[ "$cmd" = "" ]]; then
        echo 0
        return
    fi
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    fi
    port=`grep server_port $CONFIG_FILE|cut -d: -f2| tr -d \",' '`
    res=`ss -ntlp| grep ${port} | grep v2ray-plugin`
    if [[ -z "$res" ]]; then
        echo 2
    else
        echo 3
    fi
}

statusText() {
    res=`status`
    case $res in
        2)
            echo -e ${GREEN}已安装${PLAIN} ${RED}未运行${PLAIN}
            ;;
        3)
            echo -e ${GREEN}已安装${PLAIN} ${GREEN}正在运行${PLAIN}
            ;;
        *)
            echo -e ${RED}未安装${PLAIN}
            ;;
    esac
}

getData() {
    echo ""
    read -p " 请设置SS的密码（不输入则随机生成）:" PASSWORD
    [[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
    echo ""
    colorEcho $BLUE " 密码： $PASSWORD"

    echo ""
    while true
    do
        read -p " 请设置SS的端口号[1025-65535]:" PORT
        [[ -z "$PORT" ]] && PORT=`shuf -i1025-65000 -n1`
        if [[ "${PORT:0:1}" = "0" ]]; then
            echo -e " ${RED}端口不能以0开头${PLAIN}"
            exit 1
        fi
        expr $PORT + 0 &>/dev/null
        if [[ $? -eq 0 ]]; then
            if [[ $PORT -ge 1025 ]] && [[ $PORT -le 65535 ]]; then
                echo ""
                colorEcho $BLUE " 端口号： $PORT"
                echo ""
                break
            else
                colorEcho $RED " 输入错误，端口号为1025-65535的数字"
            fi
        else
            colorEcho $RED " 输入错误，端口号为1025-65535的数字"
        fi
    done
    colorEcho $RED " 请选择加密方式:" 
    echo "  1)aes-256-gcm"
    echo "  2)aes-192-gcm"
    echo "  3)aes-128-gcm"
    echo "  4)aes-256-ctr"
    echo "  5)aes-192-ctr"
    echo "  6)aes-128-ctr"
    echo "  7)aes-256-cfb"
    echo "  8)aes-192-cfb"
    echo "  9)aes-128-cfb"
    echo "  10)camellia-128-cfb"
    echo "  11)camellia-192-cfb"
    echo "  12)camellia-256-cfb"
    echo "  13)chacha20-ietf"
    echo "  14)chacha20-ietf-poly1305"
    echo "  15)xchacha20-ietf-poly1305"
    read -p " 请选择（默认aes-256-gcm）" answer
    if [[ -z "$answer" ]]; then
        METHOD="aes-256-gcm"
    else
        case $answer in
        1)
            METHOD="aes-256-gcm"
            ;;
        2)
            METHOD="aes-192-gcm"
            ;;
        3)
            METHOD="aes-128-gcm"
            ;;
        4)
            METHOD="aes-256-ctr"
            ;;
        5)
            METHOD="aes-192-ctr"
            ;;
        6)
            METHOD="aes-128-ctr"
            ;;
        7)
            METHOD="aes-256-cfb"
            ;;
        8)
            METHOD="aes-192-cfb"
            ;;
        9)
            METHOD="aes-128-cfb"
            ;;
        10)
            METHOD="camellia-128-cfb"
            ;;
        11)
            METHOD="camellia-192-cfb"
            ;;
        12)
            METHOD="camellia-256-cfb"
            ;;
        13)
            METHOD="chacha20-ietf"
            ;;
        14)
            METHOD="chacha20-ietf-poly1305"
            ;;
        15)
            METHOD="xchacha20-ietf-poly1305"
            ;;
        *)
            colorEcho $RED " 无效的选择，使用默认的aes-256-gcm"
            METHOD="aes-256-gcm"
        esac
    fi
    echo ""
    colorEcho $BLUE "加密方式： $METHOD"
}

preinstall() {
    $PMT clean all
    #echo $CMD_UPGRADE | bash
    [[ "$PMT" = "apt" ]] && $PMT update

    echo ""
    colorEcho $BULE " 安装必要软件"
    if [[ "$PMT" = "yum" ]]; then
        $CMD_INSTALL epel-release
		# Check if glibc version is 2.18 or higher
		glibc_version=$(ldd --version | grep -oP '(?<=ldd \(GNU libc\) )[0-9]+\.[0-9]+')
        if [[ "$glibc_version" < "2.18" ]]; then
             echo ""
             colorEcho $BULE " 安装 glibc 2.18"
             curl -O http://ftp.gnu.org/gnu/glibc/glibc-2.18.tar.gz
             tar zxf glibc-2.18.tar.gz
             cd glibc-2.18/
             mkdir build
             cd build/
            ../configure --prefix=/usr
             make -j2
             make install
             rm -rf glibc-2.18*
        else
             echo ""
             colorEcho $BULE " 系统已安装 glibc 2.18 或更高版本，跳过安装"
        fi
	fi	
    $CMD_INSTALL wget vim net-tools unzip tar qrencode lrzsz
    #res=`which wget 2>/dev/null`
    # [[ "$?" != "0" ]] && $CMD_INSTALL wget
    # res=`which netstat 2>/dev/null`
    # [[ "$?" != "0" ]] && $CMD_INSTALL net-tools

    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}

normalizeVersion() {
    if [ -n "$1" ]; then
        case "$1" in
            v*)
                echo "${1:1}"
            ;;
            *)
                echo "$1"
            ;;
        esac
    else
        echo ""
    fi
}

installNewVer() {
    new_ver=$1
    if ! wget "${V6_PROXY}https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${new_ver}/shadowsocks-v${new_ver}.x86_64-unknown-linux-gnu.tar.xz" -O ${NAME}.tar.xz; then
       colorEcho $RED " 下载安装文件失败！"
        exit 1
    fi
	tar -xf ${NAME}.tar.xz  -C /usr/local/bin/
    cat > $SERVICE_FILE <<-EOF
[Unit]
Description=Shadowsocks-libev Server Service
After=network.target
[Service]
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks-rust/config.json
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ${NAME}

    rm -rf shadowsocks-rust.tar.xz
    colorEcho $BLUE "ss安装成功!"
}

# Install v2ray-plugin
install_v2(){
    v2_file=$(wget -qO- https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | grep linux-amd64 | grep name | cut -f4 -d\")
    if [ -f /usr/local/bin/v2ray-plugin ];then
        echo "\033[1;32mv2ray-plugin already installed, skip.\033[0m"
    else
        if [ ! -f $v2_file ];then
            v2_url=$(wget -qO- https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | grep linux-amd64 | grep browser_download_url | cut -f4 -d\")
            wget $v2_url
        fi
        tar xf $v2_file
        mv v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
		colorEcho $BLUE " v2ray_plugin安装成功!"
        if [ ! -f /usr/local/bin/v2ray-plugin ];then
            echo "\033[1;31mFailed to install v2ray-plugin.\033[0m"
            exit 1
        fi
		rm -rf v2ray-plugin-linux-amd64*
    fi
}

update_v2(){
        v2_file=$(wget -qO- https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | grep linux-amd64 | grep name | cut -f4 -d\")
        rm -rf /usr/local/bin/v2ray-plugin
        v2_url=$(wget -qO- https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | grep linux-amd64 | grep browser_download_url | cut -f4 -d\")
        wget $v2_url
    
        tar xf $v2_file
        mv v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
		colorEcho $BLUE " v2ray_plugin安装成功!"
        if [ ! -f /usr/local/bin/v2ray-plugin ];then
            echo "\033[1;31mFailed to install v2ray-plugin.\033[0m"
            exit 1
        fi
    
}


installSS() {
    echo ""
    colorEcho $BLUE " 安装最新版SS..."

    tag_url="${V6_PROXY}https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest"
    new_ver="$(normalizeVersion "$(curl -s "${tag_url}" --connect-timeout 10| grep 'tag_name' | cut -d\" -f4)")"
    export PATH=/usr/local/bin:$PATH
    ssPath=`which ssserver 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        [[ "$new_ver" != "" ]] || new_ver="1.17.0"
        installNewVer $new_ver
    else
        ver=`ssserver -h | grep ${NAME} | grep -oE '[0-9+\.]+'`
        if [[ $ver != $new_ver ]]; then
            installNewVer $new_ver
        else
            colorEcho $YELLOW " 已安装最新版SS"
        fi
    fi
}

configSS(){
    interface="0.0.0.0"
    if [[ "$V6_PROXY" != "" ]]; then
        interface="::"
    fi

    mkdir -p /etc/${NAME}
	read -rp "请再次输入解析完成的域名: " DOMAIN
    [[ -z $DOMAIN ]] && colorEcho $YELLOW "未输入域名，无法执行操作！" 
    colorEcho $GREEN "已输入的域名：$DOMAIN" && sleep 1
    cat > $CONFIG_FILE<<-EOF
{
    "server":"$interface",
    "server_port":${PORT},
    "local_port":1080,
    "password":"${PASSWORD}",
    "timeout":600,
    "method":"${METHOD}",
    "nameserver":"8.8.8.8",
	"plugin":"v2ray-plugin",
	"plugin_opts":"server;tls;host=${DOMAIN};cert=/root/${DOMAIN}/cert.crt;key=/root/${DOMAIN}/private.key"
}
EOF
}



get_cert(){
    read -p "您确定要安装TLS证书吗？输入 'yes' 继续安装，其他任何输入将取消安装: " choice
if [[ "$choice" != "yes" ]]; then
    colorEcho $YELLOW " 取消安装TLS证书"
    return
fi
    wget -N --no-check-certificate https://raw.githubusercontent.com/yirenchengfeng1/linux/main/acme.sh && bash acme.sh
    CERT=true

}

man_cert(){
    read -p "输入 'yes' 进入证书管理界面，包括申请、删除、查看等，其他任何输入将取消: " choice
if [[ "$choice" != "yes" ]]; then
    colorEcho $YELLOW " 取消管理TLS证书"
    return
fi
    wget -N --no-check-certificate https://raw.githubusercontent.com/yirenchengfeng1/linux/main/acme.sh && bash acme.sh
    CERT=true

}

setFirewall() {
      			if [ -x "$(command -v firewall-cmd)" ]; then							  
                   firewall-cmd --permanent --add-port=${PORT}/tcp
                   firewall-cmd --permanent --add-port=${PORT}/udp
                   firewall-cmd --reload
			elif [ -x "$(command -v ufw)" ]; then								  
                    ufw allow ${PORT}/tcp
                    ufw allow ${PORT}/udp
			        ufw reload
			else
			       echo "无法配置防火墙规则。请手动配置以确保新SSH端口可用。"
			fi

}

showInfo() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi

    port=`grep server_port $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
    res=`netstat -nltp | grep ${port} | grep 'v2ray-plugin'`
    [[ -z "$res" ]] && status="${RED}已停止${PLAIN}" || status="${GREEN}正在运行${PLAIN}"
    password=`grep password $CONFIG_FILE| cut -d: -f2 | tr -d \",' '`
    method=`grep method $CONFIG_FILE| cut -d: -f2 | tr -d \",' '`
    domain=$(grep plugin_opts  $CONFIG_FILE | cut -d';' -f3 | cut -d'=' -f2)
	res1=`echo -n "${method}:${password}@${IP}:${port}" | base64 -w 0`
    res2=$(echo -n '{"path":"\/","mux":true,"host":"'$domain'","mode":"websocket","tls":true}' | base64 -w 0)
	res3=`echo -n "${method}:${password}" | base64 -w 0`
	#echo $res2
	link1="ss://${res1}?v2ray-plugin=${res2}"
	link2="ss://${res3}@${IP}:${port}/?plugin=v2ray-plugin%3btls%3bhost%3d${domain}"

	

    echo ============================================
    echo -e " ${BLUE}ss运行状态${PLAIN}：${status}"
    echo -e " ${BLUE}ss配置文件：${PLAIN}${RED}$CONFIG_FILE${PLAIN}"
    echo ""
    echo -e " ${RED}ss配置信息：${PLAIN}"
    echo -e "  ${BLUE}IP(address):${PLAIN}  ${RED}${IP}${PLAIN}"
    echo -e "  ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
    echo -e "  ${BLUE}密码(password)：${PLAIN}${RED}${password}${PLAIN}"
    echo -e "  ${BLUE}加密方式(method)：${PLAIN} ${RED}${method}${PLAIN}"
    echo -e "  ${BLUE}插件方式(plugin)：${PLAIN} ${RED}v2ray-plugin${PLAIN}"
    echo
    echo -e " ${BLUE}shadowsocks客户端订阅链接${PLAIN}： ${link2}"
	qrencode -o - -t utf8 ${link2}
    qrencode -o /tmp/Android_qrcode.png -s 10 ${link2}
	colorEcho $BLUE " shadowsocks订阅二维码已保存在/tmp/Android_qrcode.png，请下载使用..."
	
    echo -e " ${BLUE}小火箭客户端订阅链接${PLAIN}： ${link1}"	
	qrencode -o - -t utf8 ${link1}
    qrencode -o /tmp/ios_qrcode.png -s 10 ${link1}
	colorEcho $BLUE " 小火箭订阅二维码已保存在/tmp/ios_qrcode.png，请下载使用..."								 
}

showQR() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi

    port=`grep server_port $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
    res=`netstat -nltp | grep ${port} | grep 'v2ray-plugin'`
    [[ -z "$res" ]] && status="${RED}已停止${PLAIN}" || status="${GREEN}正在运行${PLAIN}"
    password=`grep password $CONFIG_FILE| cut -d: -f2 | tr -d \",' '`
    method=`grep method $CONFIG_FILE| cut -d: -f2 | tr -d \",' '`
    domain=$(grep plugin_opts  $CONFIG_FILE | cut -d';' -f3 | cut -d'=' -f2)
	res1=`echo -n "${method}:${password}@${IP}:${port}" | base64 -w 0`
    res2=$(echo -n '{"path":"\/","mux":true,"host":"'$domain'","mode":"websocket","tls":true}' | base64 -w 0)
	res3=`echo -n "${method}:${password}" | base64 -w 0`
	#echo $res2
	link1="ss://${res1}?v2ray-plugin=${res2}"
	link2="ss://${res3}@${IP}:${port}/?plugin=v2ray-plugin%3btls%3bhost%3d${domain}"
	echo -e " ${BLUE}shadowsocks客户端订阅链接${PLAIN}： ${link2}"
	qrencode -o - -t utf8 ${link2}
    qrencode -o /tmp/Android_qrcode.png -s 10 ${link2}
	colorEcho $BLUE " shadowsocks客户端订阅二维码已保存在/tmp/Android_qrcode.png，请下载使用..."
	
    echo -e " ${BLUE}小火箭客户端订阅链接${PLAIN}： ${link1}"	
	qrencode -o - -t utf8 ${link1}
    qrencode -o /tmp/ios_qrcode.png -s 10 ${link1}
	colorEcho $BLUE " 小火箭订阅二维码已保存在/tmp/ios_qrcode.png，请下载使用..."
}



install() {
    getData
    preinstall
    installSS
	install_v2
	get_cert
    configSS
    setFirewall
    start
    showInfo

}


reconfig() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi
    getData
    configSS
    restart
    setFirewall
    showInfo
}


update() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi
    installSS
	update_v2
    restart
}

start() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl restart ${NAME}
    sleep 2
    port=`grep server_port $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
    res=`ss -nltp | grep ${port} | grep v2ray-plugin`
    if [[ "$res" = "" ]]; then
        colorEcho $RED " SS启动失败，请检查端口是否被占用！"
    else
        colorEcho $BLUE " SS启动成功！"
    fi
}

restart() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi

    stop
    start
}

stop() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl stop ${NAME}
    colorEcho $BLUE " SS停止成功"
}

uninstall() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi

    echo ""
    read -p " 确定卸载SS吗？(y/n)：" answer
    [[ -z ${answer} ]] && answer="n"

    if [[ "${answer}" == "y" ]] || [[ "${answer}" == "Y" ]]; then
        systemctl stop ${NAME} && systemctl disable ${NAME}
        rm -rf $SERVICE_FILE
        cd /usr/local/bin && rm -rf sslocal ssmanager ssserver ssurl
		rm -rf /usr/local/bin/v2ray-plugin
        colorEcho $GREEN " SS卸载成功"
    fi
}

showLog() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e " ${RED}SS未安装，请先安装！${PLAIN}"
        return
    fi
    journalctl -xen --no-pager -u ${NAME}
}

menu() {
    clear
    echo "#########################################################################"
    echo -e "#              ${RED}Shadowsocks_rust 一键安装脚本${PLAIN}                            #"
    echo -e "# ${GREEN}作者${PLAIN}: 爱分享的小企鹅                                                  #"
    echo -e "# ${GREEN}Youtube频道${PLAIN}: https://youtube.com/@user-wr7rz2jq4z?si=meznAMaijxYA9S2J #"
    echo "#########################################################################"
    echo ""

    echo -e "  ${GREEN}1.${PLAIN}  安装SS和v2ray_plugin并开启tls加密（需要域名）"																				 
    echo -e "  ${GREEN}2.${PLAIN}  更新SS和v2ray_plugin"
    echo -e "  ${GREEN}3.  ${RED}卸载SS、v2ray_plugin${PLAIN}"
	echo -e "  ${GREEN}4.  ${RED}管理TLS证书${PLAIN}"
														 
    echo " -------------"
    echo -e "  ${GREEN}5.${PLAIN}  启动SS"
    echo -e "  ${GREEN}6.${PLAIN}  重启SS"
    echo -e "  ${GREEN}7.${PLAIN}  停止SS"
    echo " -------------"
    echo -e "  ${GREEN}8.${PLAIN}  查看SS配置"
    echo -e "  ${GREEN}9.${PLAIN}  查看配置二维码"
    echo -e "  ${GREEN}10.  ${RED}修改SS配置${PLAIN}"
    echo -e "  ${GREEN}11.${PLAIN} 查看SS日志"
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN} 退出"
    echo 
    echo -n " 当前状态："
    statusText
    echo 

    read -p " 请选择操作[0-11]：" answer
    case $answer in
        0)
            exit 0
            ;;
        1)
            install
            ;;
        2)		  
            update
            ;;
        3)
            uninstall
            ;;
        4)
            man_cert
            ;;					
        5)
            start
            ;;
        6)	  
            restart
            ;;
        7)
            stop
            ;;
        8)
            showInfo
            ;;
        9)
            showQR
            ;;
        10)
            reconfig
            ;;
        11)
            showLog
            ;;
        *)
            echo -e "$RED 请选择正确的操作！${PLAIN}"
            exit 1
            ;;
    esac
}

checkSystem

action=$1
[[ -z $1 ]] && action=menu
case "$action" in
    menu|install|update|uninstall|man_cert|start|restart|stop|showInfo|showQR|showLog)
        ${action}
        ;;
    *)
        echo " 参数错误"
        echo " 用法: `basename $0` [menu|install|update|uninstall|man_cert|start|restart|stop|showInfo|showQR|showLog]"
        ;;
esac
