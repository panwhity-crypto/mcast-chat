/*
 * main.c —— 程序入口与命令行参数
 *
 *   ./mcastchat                     图形界面（启动对话框中填写昵称等）
 *   ./mcastchat --name 张三          直接以指定昵称进入
 *   ./mcastchat --cli --name 李四    命令行界面
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "net.h"
#include "node.h"

#ifdef HAVE_GTK
#include "gui.h"
#endif

static void usage(const char *prog)
{
    printf("用法：%s [选项]\n"
           "带文件传输功能的多播聊天工具\n\n"
           "  --name 昵称          昵称（图形界面下不填则弹出对话框）\n"
           "  --group 地址         多播组地址（默认 239.1.2.3）\n"
           "  --port 端口          多播端口（默认 50000）\n"
           "  --iface IP           用于多播的本机网卡 IP（默认自动选择）\n"
           "  --ttl N              多播 TTL（默认 1，不出本网段）\n"
           "  --no-encrypt         关闭加密，便于抓包观察明文\n"
           "  --retransmit         开启文件丢包重传（NACK）\n"
           "  --rate KB/s          文件发送限速（默认 2048）\n"
           "  --download-dir 目录  接收文件保存目录（默认 ~/McastChat）\n"
           "  --cli                使用命令行界面\n"
           "  -h, --help           显示帮助\n",
           prog);
}

int main(int argc, char **argv)
{
    node_config cfg;
    node_config_default(&cfg);
    int use_cli = 0, name_given = 0;

    static struct option opts[] = {
        {"name", required_argument, 0, 'n'},      {"group", required_argument, 0, 'g'},
        {"port", required_argument, 0, 'p'},      {"iface", required_argument, 0, 'i'},
        {"ttl", required_argument, 0, 't'},       {"no-encrypt", no_argument, 0, 'E'},
        {"retransmit", no_argument, 0, 'R'},      {"rate", required_argument, 0, 'r'},
        {"download-dir", required_argument, 0, 'd'}, {"cli", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},            {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
        switch (c) {
        case 'n': snprintf(cfg.name, sizeof(cfg.name), "%s", optarg); name_given = 1; break;
        case 'g': snprintf(cfg.group, sizeof(cfg.group), "%s", optarg); break;
        case 'p': cfg.port = atoi(optarg); break;
        case 'i': snprintf(cfg.iface, sizeof(cfg.iface), "%s", optarg); break;
        case 't': cfg.ttl = atoi(optarg); break;
        case 'E': cfg.encrypt = 0; break;
        case 'R': cfg.retransmit = 1; break;
        case 'r': cfg.rate_kbps = atoi(optarg); break;
        case 'd': snprintf(cfg.download_dir, sizeof(cfg.download_dir), "%s", optarg); break;
        case 'c': use_cli = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (!is_multicast_addr(cfg.group)) {
        fprintf(stderr, "%s 不是多播地址\n", cfg.group);
        return 2;
    }
    if (cfg.port <= 0 || cfg.port > 65535) {
        fprintf(stderr, "端口不合法\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (use_cli)
        return run_cli(&cfg);
#ifdef HAVE_GTK
    return run_gui(&cfg, name_given, argc, argv);
#else
    (void)name_given;
    fprintf(stderr, "本程序编译时未包含 GTK 图形界面，使用 --cli 进入命令行模式\n");
    return run_cli(&cfg);
#endif
}
