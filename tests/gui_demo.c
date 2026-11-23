/*
 * gui_demo.c —— 在一个进程里打开 3 个聊天窗口，自动走完整流程并截图
 * 用法：xvfb-run -s "-screen 0 3100x720x24" ./build/gui_demo docs/screenshots
 */
#include <gtk/gtk.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "gui.h"

static const char *outdir;
static gui_window *win[3];

static void pump(double secs)
{
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        while (gtk_events_pending())
            gtk_main_iteration_do(FALSE);
        g_usleep(20000);
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while ((t.tv_sec - t0.tv_sec) + (t.tv_nsec - t0.tv_nsec) / 1e9 < secs);
}

static void shot(int i, const char *name)
{
    pump(0.4);
    GtkWidget *w = gui_window_widget(win[i]);
    GdkWindow *gw = gtk_widget_get_window(w);
    int x, y;
    gdk_window_get_origin(gw, &x, &y);
    /* 从根窗口截取，这样叠在上面的对话框也会被截进来 */
    GdkPixbuf *pb = gdk_pixbuf_get_from_window(gdk_get_default_root_window(), x, y, gdk_window_get_width(gw),
                                               gdk_window_get_height(gw));
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.png", outdir, name);
    gdk_pixbuf_save(pb, path, "png", NULL, NULL);
    g_object_unref(pb);
    printf("saved %s\n", path);
}

static gui_window *open_win(const char *name, int idx)
{
    node_config c;
    node_config_default(&c);
    snprintf(c.name, sizeof(c.name), "%s", name);
    c.port = 52333;
    snprintf(c.download_dir, sizeof(c.download_dir), "/tmp/mc_demo_dl");
    char err[256];
    gui_window *w = gui_window_create(&c, 0, err, sizeof(err));
    if (!w) {
        fprintf(stderr, "%s\n", err);
        exit(1);
    }
    gtk_window_move(GTK_WINDOW(gui_window_widget(w)), idx * 1030, 0);
    return w;
}

static void write_wav(const char *path, int secs)
{
    FILE *f = fopen(path, "wb");
    int rate = 22050, n = rate * secs, bytes = n * 2;
    unsigned char h[44] = "RIFF";
    #define LE32(o, v) (h[o] = (v) & 255, h[o + 1] = ((v) >> 8) & 255, h[o + 2] = ((v) >> 16) & 255, h[o + 3] = ((v) >> 24) & 255)
    LE32(4, 36 + bytes);
    memcpy(h + 8, "WAVEfmt ", 8);
    LE32(16, 16);
    h[20] = 1; h[22] = 1;
    LE32(24, rate);
    LE32(28, rate * 2);
    h[32] = 2; h[34] = 16;
    memcpy(h + 36, "data", 4);
    LE32(40, bytes);
    fwrite(h, 1, 44, f);
    for (int i = 0; i < n; i++) {
        short s = (short)(8000 * sin(2 * M_PI * 440 * i / rate));
        fwrite(&s, 2, 1, f);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    outdir = argc > 1 ? argv[1] : ".";
    gtk_init(&argc, &argv);
    if (system("rm -rf /tmp/mc_demo_dl /tmp/mc_demo_src && mkdir -p /tmp/mc_demo_src") != 0)
        return 1;
    write_wav("/tmp/mc_demo_src/会议录音.wav", 6);
    FILE *f = fopen("/tmp/mc_demo_src/课程演示.mp4", "wb");
    static unsigned char junk[2500000];
    random_bytes(junk, sizeof(junk));
    fwrite(junk, 1, sizeof(junk), f);
    fclose(f);

    char err[256];
    win[0] = open_win("张三", 0);
    pump(3);
    win[1] = open_win("李四", 1);
    pump(0.5);
    win[2] = open_win("王五", 2);
    pump(3);
    node *a = gui_window_node(win[0]), *b = gui_window_node(win[1]), *c = gui_window_node(win[2]);

    node_send_chat(a, "大家好，这是一条多播消息", err, sizeof(err));
    pump(0.3);
    node_send_chat(b, "收到！李四在线", err, sizeof(err));
    pump(0.3);
    node_send_chat(c, "王五也收到了", err, sizeof(err));
    pump(0.6);
    shot(0, "01_chat_admin");
    shot(1, "02_chat_member");

    node_send_file(a, "/tmp/mc_demo_src/会议录音.wav", err, sizeof(err));
    pump(0.2);
    node_send_file(b, "/tmp/mc_demo_src/课程演示.mp4", err, sizeof(err));
    pump(0.7);
    shot(2, "03_file_in_progress");
    pump(4);
    shot(2, "04_file_done");
    shot(0, "05_file_admin_view");

    char cid[17];
    node_id_hex(c, cid);
    gui_select_member(win[0], cid);
    pump(0.3);
    shot(0, "06_before_kick");
    node_kick(a, cid, err, sizeof(err));
    pump(1.5);
    node_send_chat(a, "王五已被移出，这条消息他解不开", err, sizeof(err));
    pump(2.5); /* 等被删除者的提示框画完 */
    shot(0, "07_after_kick_admin");
    shot(1, "08_after_kick_member");
    shot(2, "09_kicked");

    gtk_widget_destroy(gui_window_widget(win[0])); /* 管理员下线 */
    pump(3);
    node_send_chat(b, "张三下线了，我接任管理员", err, sizeof(err));
    pump(0.6);
    shot(1, "10_admin_handover");
    exit(0);
}
