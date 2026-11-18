/* gui.h —— GTK3 图形界面 */
#ifndef MC_GUI_H
#define MC_GUI_H

#include <gtk/gtk.h>

#include "node.h"

typedef struct gui_window gui_window;

/* 创建窗口与节点并加入多播组；失败返回 NULL 并写入 err */
gui_window *gui_window_create(const node_config *cfg, int quit_on_close, char *err, size_t errlen);
node *gui_window_node(gui_window *w);
GtkWidget *gui_window_widget(gui_window *w);
void gui_select_member(gui_window *w, const char *id_hex); /* 演示脚本用 */

/* 程序入口：name_given 为 0 时先弹出启动对话框 */
int run_gui(node_config *cfg, int name_given, int argc, char **argv);

#endif
