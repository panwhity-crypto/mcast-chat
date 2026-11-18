/*
 * gui.c —— GTK3 图形界面
 *
 * 左侧：聊天记录 + 输入框 + 发送 / 发送文件按钮（也可把文件拖进窗口发送）
 * 右侧：组成员列表 + 删除成员按钮（仅管理员可用）+ 文件传输列表
 * 底部：多播组、身份、加密状态、收发包统计
 *
 * 节点的事件回调在网络线程中触发，这里把事件复制一份，用 g_idle_add
 * 交给 GTK 主线程处理，界面控件只在主线程中访问。
 */
#include "gui.h"

#include <string.h>
#include <time.h>

#include "filexfer.h"
#include "members.h"
#include "net.h"

enum { MC_NAME_MARKUP, MC_ID, MC_SELF, MC_N };
enum { TC_FID, TC_FILE, TC_FROM, TC_PROGRESS, TC_PROGRESS_TEXT, TC_STATUS, TC_PATH, TC_DONE, TC_N };

struct gui_window {
    node *n;
    int quit_on_close;
    int kicked_shown;
    GtkWidget *win, *chat, *entry, *btn_send, *btn_file, *btn_kick, *lbl_role, *lbl_members;
    GtkWidget *members_view, *files_view, *status;
    GtkTextBuffer *buf;
    GtkListStore *members, *files;
    guint stats_timer;
};

static const char *CSS =
    "window { background: #f4f6f8; }"
    "textview text { background: #ffffff; }"
    ".panel { background: #ffffff; border: 1px solid #dde2e7; border-radius: 6px; }"
    ".section { font-weight: bold; color: #333333; }"
    ".hint { color: #666666; }"
    ".statusbar { color: #444444; padding: 4px 8px; font-size: 90%; }"
    "button.primary { background: #2f6feb; color: white; }"
    "button.primary:disabled { background: #b8c9ee; color: #f4f6f8; }"
    "button.danger { color: #c62828; }";

/* ======================================================== 小工具 */

static void fmt_time(double ts, char out[16])
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, 16, "%H:%M:%S", &tm);
}

static void fmt_size(uint64_t n, char *out, size_t cap)
{
    if (n < 1024)
        snprintf(out, cap, "%llu B", (unsigned long long)n);
    else if (n < 1024 * 1024)
        snprintf(out, cap, "%.1f KB", n / 1024.0);
    else
        snprintf(out, cap, "%.1f MB", n / 1048576.0);
}

static void scroll_to_end(gui_window *w)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(w->buf, &end);
    GtkTextMark *mark = gtk_text_buffer_get_mark(w->buf, "end");
    gtk_text_buffer_move_mark(w->buf, mark, &end);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(w->chat), mark);
}

static void insert_tagged(gui_window *w, const char *text, const char *tag)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(w->buf, &end);
    if (tag)
        gtk_text_buffer_insert_with_tags_by_name(w->buf, &end, text, -1, tag, NULL);
    else
        gtk_text_buffer_insert(w->buf, &end, text, -1);
}

static void append_system(gui_window *w, const char *text, double ts)
{
    char t[16], line[MC_MAX_TEXT + 64];
    fmt_time(ts ? ts : (double)time(NULL), t);
    snprintf(line, sizeof(line), "[%s] %s\n", t, text);
    insert_tagged(w, line, "sys");
    scroll_to_end(w);
}

static void append_chat(gui_window *w, const node_event *ev)
{
    char t[16], head[96];
    fmt_time(ev->ts, t);
    snprintf(head, sizeof(head), "%s%s", ev->name, ev->self ? "（我）" : "");
    insert_tagged(w, head, ev->self ? "name_self" : "name_other");
    insert_tagged(w, "  ", NULL);
    insert_tagged(w, t, "time");
    insert_tagged(w, "\n", NULL);
    insert_tagged(w, ev->text, "msg");
    insert_tagged(w, "\n", NULL);
    scroll_to_end(w);
}

/* 优先用桌面默认程序打开（xdg-open 同一机制），失败退回 ffplay */
static void open_path(gui_window *w, const char *path)
{
    GError *err = NULL;
    char *uri = g_filename_to_uri(path, NULL, NULL);
    gboolean ok = uri && g_app_info_launch_default_for_uri(uri, NULL, &err);
    g_free(uri);
    if (!ok) {
        g_clear_error(&err);
        const char *argv1[] = {"xdg-open", path, NULL};
        ok = g_spawn_async(NULL, (char **)argv1, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL);
    }
    if (!ok) {
        const char *argv2[] = {"ffplay", "-autoexit", path, NULL};
        ok = g_spawn_async(NULL, (char **)argv2, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL);
    }
    if (!ok)
        append_system(w, "无法打开文件：系统中没有可用的播放器（可安装 vlc 或 ffmpeg）", 0);
}

static gboolean on_link_event(GtkTextTag *tag, GObject *obj, GdkEvent *ev, GtkTextIter *it, gpointer data)
{
    if (ev->type == GDK_BUTTON_RELEASE && ev->button.button == 1) {
        const char *path = g_object_get_data(G_OBJECT(tag), "path");
        if (path)
            open_path(data, path);
        return TRUE;
    }
    return FALSE;
}

static void append_file_received(gui_window *w, const node_event *ev)
{
    char t[16], line[512];
    fmt_time(ev->ts, t);
    snprintf(line, sizeof(line), "[%s] 收到 %s 的文件 ", t, ev->name);
    insert_tagged(w, line, "sys");
    insert_tagged(w, ev->fname, "bold");
    insert_tagged(w, "（SHA-256 校验通过）  ", "sys");
    GtkTextTag *tag = gtk_text_buffer_create_tag(w->buf, NULL, "foreground", "#2f6feb",
                                                 "underline", PANGO_UNDERLINE_SINGLE, NULL);
    g_object_set_data_full(G_OBJECT(tag), "path", g_strdup(ev->path), g_free);
    g_signal_connect(tag, "event", G_CALLBACK(on_link_event), w);
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(w->buf, &end);
    gtk_text_buffer_insert_with_tags(w->buf, &end, is_media_file(ev->fname) ? "▶ 播放" : "打开", -1, tag, NULL);
    insert_tagged(w, "\n", NULL);
    scroll_to_end(w);
}

/* ======================================================== 状态刷新 */

static char *selected_member(gui_window *w, gboolean *is_self)
{
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(w->members_view));
    GtkTreeModel *model;
    GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, &model, &it))
        return NULL;
    char *id;
    gboolean self;
    gtk_tree_model_get(model, &it, MC_ID, &id, MC_SELF, &self, -1);
    if (is_self)
        *is_self = self;
    return id;
}

static void update_buttons(gui_window *w)
{
    node *n = w->n;
    int ready = node_ready(n), kicked = node_kicked(n), admin = node_is_admin(n);
    gtk_widget_set_sensitive(w->entry, ready);
    gtk_widget_set_sensitive(w->btn_send, ready);
    gtk_widget_set_sensitive(w->btn_file, ready);
    if (kicked)
        gtk_entry_set_placeholder_text(GTK_ENTRY(w->entry), "你已被移出群组");
    else
        gtk_entry_set_placeholder_text(GTK_ENTRY(w->entry), ready ? "输入消息，回车发送；也可把文件拖进窗口发送"
                                                                  : "等待管理员分发组密钥…");
    gboolean self = TRUE;
    char *id = selected_member(w, &self);
    gtk_widget_set_sensitive(w->btn_kick, admin && !kicked && id && !self);
    gtk_widget_set_visible(w->btn_kick, admin && !kicked);
    g_free(id);
    gtk_label_set_text(GTK_LABEL(w->lbl_role), kicked ? "" : admin ? "你是管理员：选中成员后可将其删除（删除后自动更换组密钥）"
                                                                    : "只有管理员可以删除成员");
}

static gboolean refresh_status(gpointer data)
{
    gui_window *w = data;
    node *n = w->n;
    const node_config *c = node_get_config(n);
    unsigned long s, r, d;
    node_stats(n, &s, &r, &d);
    char crypto[96], text[512];
    if (node_kicked(n))
        snprintf(crypto, sizeof(crypto), "已被移出群组，组密钥已失效");
    else if (!c->encrypt)
        snprintf(crypto, sizeof(crypto), "未加密（明文）");
    else if (node_ready(n))
        snprintf(crypto, sizeof(crypto), "RSA-2048 + AES-256-GCM，密钥版本 %u", node_epoch(n));
    else
        snprintf(crypto, sizeof(crypto), "加密：等待密钥");
    snprintf(text, sizeof(text), "多播组 %s:%d   网卡 %s   TTL %d  ｜  身份：%s  ｜  %s  ｜  发送 %lu 包 / 接收 %lu 包%s",
             c->group, c->port, c->iface, c->ttl, node_is_admin(n) ? "管理员" : "成员", crypto, s, r,
             c->retransmit ? "  ｜  重传开" : "");
    gtk_label_set_text(GTK_LABEL(w->status), text);
    return G_SOURCE_CONTINUE;
}

static void render_members(gui_window *w)
{
    if (node_kicked(w->n))
        return;
    char *keep = selected_member(w, NULL);
    member_info list[MAX_MEMBERS + 1];
    int cnt = node_members(w->n, list, MAX_MEMBERS + 1);
    int encrypt = node_get_config(w->n)->encrypt;
    gtk_list_store_clear(w->members);
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(w->members_view));
    for (int i = 0; i < cnt; i++) {
        char tags[96] = "";
        if (list[i].admin)
            strcat(tags, "★管理员 ");
        if (list[i].self)
            strcat(tags, "我 ");
        if (encrypt && !list[i].has_key)
            strcat(tags, "等待密钥 ");
        char idshort[9];
        snprintf(idshort, sizeof(idshort), "%.8s", list[i].id);
        char *markup = g_markup_printf_escaped(
            "<b>%s</b>  <span foreground='%s'>%s</span>\n<small><span foreground='#777777'>%s    ID %s</span></small>",
            list[i].name, list[i].admin ? "#b26a00" : "#2f6feb", tags, list[i].addr, idshort);
        GtkTreeIter it;
        gtk_list_store_append(w->members, &it);
        gtk_list_store_set(w->members, &it, MC_NAME_MARKUP, markup, MC_ID, list[i].id, MC_SELF, list[i].self, -1);
        g_free(markup);
        if (keep && strcmp(keep, list[i].id) == 0)
            gtk_tree_selection_select_iter(sel, &it);
    }
    g_free(keep);
    char title[64];
    snprintf(title, sizeof(title), "组成员（%d 人）", cnt);
    gtk_label_set_text(GTK_LABEL(w->lbl_members), title);
    update_buttons(w);
}

static const char *status_text(int s)
{
    switch (s) {
    case TS_SENDING: return "发送中";
    case TS_SENT: return "已发送";
    case TS_RECEIVING: return "接收中";
    case TS_DONE: return "接收完成";
    default: return "失败";
    }
}

static void on_transfer(gui_window *w, const node_event *ev)
{
    GtkTreeIter it;
    GtkTreeModel *model = GTK_TREE_MODEL(w->files);
    gboolean found = FALSE, valid = gtk_tree_model_get_iter_first(model, &it);
    while (valid && !found) {
        char *fid;
        gtk_tree_model_get(model, &it, TC_FID, &fid, -1);
        found = strcmp(fid, ev->fid) == 0;
        g_free(fid);
        if (!found)
            valid = gtk_tree_model_iter_next(model, &it);
    }
    if (!found) {
        char size[32], label[400];
        fmt_size(ev->size, size, sizeof(size));
        snprintf(label, sizeof(label), "%s  (%s)", ev->fname, size);
        gtk_list_store_append(w->files, &it);
        gtk_list_store_set(w->files, &it, TC_FID, ev->fid, TC_FILE, label, TC_FROM, ev->outgoing ? "我" : ev->name,
                           TC_PATH, ev->outgoing ? ev->path : "", TC_DONE, FALSE, -1);
        if (!ev->outgoing) {
            char line[512];
            snprintf(line, sizeof(line), "%s 正在发送文件 %s（%s）", ev->name, ev->fname, size);
            append_system(w, line, ev->ts);
        }
    }
    int pct = (ev->status == TS_DONE || ev->status == TS_SENT) ? 100
              : ev->total ? (int)((uint64_t)ev->done * 100 / ev->total) : 0;
    char pt[16], st[256];
    snprintf(pt, sizeof(pt), "%d%%", pct);
    if (ev->reason[0])
        snprintf(st, sizeof(st), "%s：%s", status_text(ev->status), ev->reason);
    else
        snprintf(st, sizeof(st), "%s", status_text(ev->status));
    gtk_list_store_set(w->files, &it, TC_PROGRESS, pct, TC_PROGRESS_TEXT, pt, TC_STATUS, st, -1);
    if (ev->status == TS_DONE) {
        gtk_list_store_set(w->files, &it, TC_PATH, ev->path, TC_DONE, TRUE, -1);
        append_file_received(w, ev);
    } else if (ev->status == TS_FAILED) {
        char line[512];
        snprintf(line, sizeof(line), "文件 %s 传输失败：%s", ev->fname, ev->reason);
        append_system(w, line, ev->ts);
    } else if (ev->status == TS_SENT) {
        char line[512];
        snprintf(line, sizeof(line), "文件 %s 已多播发送完毕（%s）", ev->fname, ev->reason);
        append_system(w, line, ev->ts);
    }
}

static void on_kicked(gui_window *w, const char *by)
{
    w->kicked_shown = 1;
    gtk_list_store_clear(w->members);
    gtk_label_set_text(GTK_LABEL(w->lbl_members), "组成员（已被移出）");
    char title[128], line[256];
    snprintf(title, sizeof(title), "多播聊天 - %s（已被移出）", node_get_config(w->n)->name);
    gtk_window_set_title(GTK_WINDOW(w->win), title);
    snprintf(line, sizeof(line), "你已被 %s 移出群组，组密钥已更换，无法再收发消息", by);
    append_system(w, line, 0);
    update_buttons(w);
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(w->win), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_WARNING,
                                          GTK_BUTTONS_OK, "你已被管理员 %s 移出群组。", by);
    g_signal_connect(d, "response", G_CALLBACK(gtk_widget_destroy), NULL);
    gtk_widget_show(d); /* 非模态，不阻塞事件循环 */
}

/* ======================================================== 事件分发 */

typedef struct {
    gui_window *w;
    node_event ev;
} queued_event;

static gboolean handle_event(gpointer data)
{
    queued_event *q = data;
    gui_window *w = q->w;
    const node_event *ev = &q->ev;
    switch (ev->kind) {
    case EV_CHAT: append_chat(w, ev); break;
    case EV_SYSTEM: append_system(w, ev->text, ev->ts); break;
    case EV_MEMBERS: render_members(w); break;
    case EV_ROLE:
    case EV_KEY: update_buttons(w); break;
    case EV_TRANSFER: on_transfer(w, ev); break;
    case EV_KICKED: on_kicked(w, ev->name); break;
    }
    refresh_status(w);
    g_free(q);
    return G_SOURCE_REMOVE;
}

/* 在网络线程中调用：复制事件，交给主线程 */
static void gui_event_cb(const node_event *ev, void *user)
{
    queued_event *q = g_malloc(sizeof(queued_event));
    q->w = user;
    q->ev = *ev;
    g_idle_add(handle_event, q);
}

/* ======================================================== 用户操作 */

static void show_error(gui_window *w, const char *title, const char *msg)
{
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(w->win), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
                                          GTK_BUTTONS_OK, "%s", title);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static void on_send(GtkWidget *b, gpointer data)
{
    gui_window *w = data;
    const char *text = gtk_entry_get_text(GTK_ENTRY(w->entry));
    if (!text[0])
        return;
    char err[256];
    if (node_send_chat(w->n, text, err, sizeof(err)) != 0)
        show_error(w, "发送失败", err);
    else
        gtk_entry_set_text(GTK_ENTRY(w->entry), "");
}

static void send_file(gui_window *w, const char *path)
{
    char err[512];
    if (node_send_file(w->n, path, err, sizeof(err)) != 0)
        show_error(w, "发送失败", err);
}

static void on_pick_file(GtkWidget *b, gpointer data)
{
    gui_window *w = data;
    GtkWidget *d = gtk_file_chooser_dialog_new("选择要多播发送的文件", GTK_WINDOW(w->win), GTK_FILE_CHOOSER_ACTION_OPEN,
                                               "取消", GTK_RESPONSE_CANCEL, "发送", GTK_RESPONSE_ACCEPT, NULL);
    GtkFileFilter *media = gtk_file_filter_new(), *all = gtk_file_filter_new();
    gtk_file_filter_set_name(media, "音视频文件");
    const char *pats[] = {"*.mp3", "*.wav", "*.flac", "*.m4a", "*.ogg", "*.mp4", "*.mkv", "*.avi", "*.mov", "*.webm", NULL};
    for (int i = 0; pats[i]; i++)
        gtk_file_filter_add_pattern(media, pats[i]);
    gtk_file_filter_set_name(all, "所有文件");
    gtk_file_filter_add_pattern(all, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(d), all);
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(d), media);
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
        gtk_widget_destroy(d);
        send_file(w, path);
        g_free(path);
    } else {
        gtk_widget_destroy(d);
    }
}

static void on_drop(GtkWidget *wid, GdkDragContext *ctx, gint x, gint y, GtkSelectionData *sd, guint info,
                    guint time_, gpointer data)
{
    gui_window *w = data;
    char **uris = gtk_selection_data_get_uris(sd);
    for (int i = 0; uris && uris[i]; i++) {
        char *path = g_filename_from_uri(uris[i], NULL, NULL);
        if (path && node_ready(w->n))
            send_file(w, path);
        g_free(path);
    }
    g_strfreev(uris);
    gtk_drag_finish(ctx, TRUE, FALSE, time_);
}

static void on_kick(GtkWidget *b, gpointer data)
{
    gui_window *w = data;
    gboolean self;
    char *id = selected_member(w, &self);
    if (!id || self) {
        g_free(id);
        return;
    }
    member_info list[MAX_MEMBERS + 1];
    int cnt = node_members(w->n, list, MAX_MEMBERS + 1);
    const char *name = id;
    for (int i = 0; i < cnt; i++)
        if (strcmp(list[i].id, id) == 0)
            name = list[i].name;
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(w->win), GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION,
                                          GTK_BUTTONS_YES_NO, "确定将 %s 移出群组吗？", name);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d),
                                             "移出后将更换组密钥，对方无法再解密任何新消息。");
    int resp = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    if (resp == GTK_RESPONSE_YES) {
        char err[256];
        if (node_kick(w->n, id, err, sizeof(err)) != 0)
            show_error(w, "无法删除", err);
    }
    g_free(id);
}

static void open_selected_file(gui_window *w)
{
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(w->files_view));
    GtkTreeModel *model;
    GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, &model, &it))
        return;
    char *path;
    gtk_tree_model_get(model, &it, TC_PATH, &path, -1);
    if (path && path[0])
        open_path(w, path);
    g_free(path);
}

static void on_play(GtkWidget *b, gpointer data) { open_selected_file(data); }

static void on_file_activated(GtkTreeView *tv, GtkTreePath *p, GtkTreeViewColumn *c, gpointer data)
{
    open_selected_file(data);
}

static void on_open_dir(GtkWidget *b, gpointer data)
{
    gui_window *w = data;
    mkdir_p(node_download_dir(w->n));
    open_path(w, node_download_dir(w->n));
}

static void on_member_sel(GtkTreeSelection *s, gpointer data) { update_buttons(data); }

static void on_destroy(GtkWidget *wid, gpointer data)
{
    gui_window *w = data;
    g_source_remove(w->stats_timer);
    node_destroy(w->n); /* 发送 BYE、离开多播组 */
    /* 队列中可能还有未处理的事件引用 w，故不释放 w（进程即将退出） */
    if (w->quit_on_close)
        gtk_main_quit();
}

/* ======================================================== 布局 */

static GtkWidget *framed(GtkWidget *child)
{
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), child);
    gtk_style_context_add_class(gtk_widget_get_style_context(sw), "panel");
    return sw;
}

static GtkWidget *section_label(const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(l), "section");
    return l;
}

static void build(gui_window *w)
{
    w->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[128];
    snprintf(title, sizeof(title), "多播聊天 - %s", node_get_config(w->n)->name);
    gtk_window_set_title(GTK_WINDOW(w->win), title);
    gtk_window_set_default_size(GTK_WINDOW(w->win), 1000, 640);
    g_signal_connect(w->win, "destroy", G_CALLBACK(on_destroy), w);

    /* 左：聊天 */
    w->chat = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(w->chat), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(w->chat), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(w->chat), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(w->chat), 10);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(w->chat), 10);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(w->chat), 8);
    w->buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w->chat));
    gtk_text_buffer_create_tag(w->buf, "name_self", "foreground", "#2f6feb", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(w->buf, "name_other", "foreground", "#1a7f37", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(w->buf, "time", "foreground", "#999999", "scale", 0.85, NULL);
    gtk_text_buffer_create_tag(w->buf, "msg", "pixels-below-lines", 6, NULL);
    gtk_text_buffer_create_tag(w->buf, "sys", "foreground", "#8a8f98", "scale", 0.85, NULL);
    gtk_text_buffer_create_tag(w->buf, "bold", "weight", PANGO_WEIGHT_BOLD, "scale", 0.85, NULL);
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(w->buf, &end);
    gtk_text_buffer_create_mark(w->buf, "end", &end, FALSE);

    w->entry = gtk_entry_new();
    g_signal_connect(w->entry, "activate", G_CALLBACK(on_send), w);
    w->btn_send = gtk_button_new_with_label("发送");
    gtk_style_context_add_class(gtk_widget_get_style_context(w->btn_send), "primary");
    g_signal_connect(w->btn_send, "clicked", G_CALLBACK(on_send), w);
    w->btn_file = gtk_button_new_with_label("发送文件…");
    g_signal_connect(w->btn_file, "clicked", G_CALLBACK(on_pick_file), w);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(row), w->entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(row), w->btn_send, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), w->btn_file, FALSE, FALSE, 0);
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(left), framed(w->chat), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(left), row, FALSE, FALSE, 0);

    /* 右：成员 */
    w->lbl_members = section_label("组成员");
    w->members = gtk_list_store_new(MC_N, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
    w->members_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(w->members));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(w->members_view), FALSE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(w->members_view),
                                gtk_tree_view_column_new_with_attributes("成员", gtk_cell_renderer_text_new(),
                                                                         "markup", MC_NAME_MARKUP, NULL));
    g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(w->members_view)), "changed",
                     G_CALLBACK(on_member_sel), w);
    w->lbl_role = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(w->lbl_role), 0);
    gtk_label_set_line_wrap(GTK_LABEL(w->lbl_role), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(w->lbl_role), "hint");
    w->btn_kick = gtk_button_new_with_label("删除选中成员");
    gtk_style_context_add_class(gtk_widget_get_style_context(w->btn_kick), "danger");
    g_signal_connect(w->btn_kick, "clicked", G_CALLBACK(on_kick), w);

    /* 右：文件 */
    w->files = gtk_list_store_new(TC_N, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING,
                                  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
    w->files_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(w->files));
    GtkCellRenderer *rt = gtk_cell_renderer_text_new();
    g_object_set(rt, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
    GtkTreeViewColumn *c0 = gtk_tree_view_column_new_with_attributes("文件", rt, "text", TC_FILE, NULL);
    gtk_tree_view_column_set_expand(c0, TRUE);
    gtk_tree_view_column_set_min_width(c0, 140);
    gtk_tree_view_append_column(GTK_TREE_VIEW(w->files_view), c0);
    gtk_tree_view_append_column(GTK_TREE_VIEW(w->files_view),
                                gtk_tree_view_column_new_with_attributes("来源", gtk_cell_renderer_text_new(),
                                                                         "text", TC_FROM, NULL));
    GtkTreeViewColumn *cp = gtk_tree_view_column_new_with_attributes("进度", gtk_cell_renderer_progress_new(),
                                                                      "value", TC_PROGRESS, "text",
                                                                      TC_PROGRESS_TEXT, NULL);
    gtk_tree_view_column_set_min_width(cp, 80);
    gtk_tree_view_append_column(GTK_TREE_VIEW(w->files_view), cp);
    gtk_tree_view_append_column(GTK_TREE_VIEW(w->files_view),
                                gtk_tree_view_column_new_with_attributes("状态", gtk_cell_renderer_text_new(),
                                                                         "text", TC_STATUS, NULL));
    g_signal_connect(w->files_view, "row-activated", G_CALLBACK(on_file_activated), w);
    GtkWidget *btn_play = gtk_button_new_with_label("播放 / 打开");
    g_signal_connect(btn_play, "clicked", G_CALLBACK(on_play), w);
    GtkWidget *btn_dir = gtk_button_new_with_label("下载目录");
    g_signal_connect(btn_dir, "clicked", G_CALLBACK(on_open_dir), w);
    GtkWidget *frow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_set_homogeneous(GTK_BOX(frow), TRUE);
    gtk_box_pack_start(GTK_BOX(frow), btn_play, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(frow), btn_dir, TRUE, TRUE, 0);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(right), w->lbl_members, FALSE, FALSE, 0);
    GtkWidget *mframe = framed(w->members_view);
    gtk_widget_set_size_request(mframe, -1, 180);
    gtk_box_pack_start(GTK_BOX(right), mframe, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(right), w->lbl_role, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(right), w->btn_kick, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(right), section_label("文件传输"), FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(right), framed(w->files_view), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(right), frow, FALSE, FALSE, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_pack1(GTK_PANED(paned), left, TRUE, FALSE);
    gtk_paned_pack2(GTK_PANED(paned), right, FALSE, FALSE);
    gtk_paned_set_position(GTK_PANED(paned), 590);

    w->status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(w->status), 0);
    gtk_label_set_ellipsize(GTK_LABEL(w->status), PANGO_ELLIPSIZE_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(w->status), "statusbar");

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(root), 10);
    gtk_box_pack_start(GTK_BOX(root), paned, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(root), w->status, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(w->win), root);

    /* 拖放文件即发送 */
    gtk_drag_dest_set(w->win, GTK_DEST_DEFAULT_ALL, NULL, 0, GDK_ACTION_COPY);
    gtk_drag_dest_add_uri_targets(w->win);
    g_signal_connect(w->win, "drag-data-received", G_CALLBACK(on_drop), w);
}

static void install_css(void)
{
    static int done;
    if (done)
        return;
    done = 1;
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(p),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

/* ======================================================== 对外接口 */

gui_window *gui_window_create(const node_config *cfg, int quit_on_close, char *err, size_t errlen)
{
    install_css();
    gui_window *w = g_new0(gui_window, 1);
    w->quit_on_close = quit_on_close;
    w->n = node_create(cfg, gui_event_cb, w);
    if (!w->n) {
        snprintf(err, errlen, "创建节点失败（生成 RSA 密钥出错）");
        g_free(w);
        return NULL;
    }
    build(w);
    update_buttons(w);
    if (node_start(w->n, err, errlen) != 0) {
        g_signal_handlers_disconnect_by_func(w->win, G_CALLBACK(on_destroy), w);
        gtk_widget_destroy(w->win);
        node_destroy(w->n);
        g_free(w);
        return NULL;
    }
    w->stats_timer = g_timeout_add_seconds(1, refresh_status, w);
    refresh_status(w);
    gtk_widget_show_all(w->win);
    update_buttons(w);
    return w;
}

node *gui_window_node(gui_window *w) { return w->n; }
GtkWidget *gui_window_widget(gui_window *w) { return w->win; }

void gui_select_member(gui_window *w, const char *id_hex)
{
    GtkTreeModel *model = GTK_TREE_MODEL(w->members);
    GtkTreeIter it;
    gboolean valid = gtk_tree_model_get_iter_first(model, &it);
    while (valid) {
        char *id;
        gtk_tree_model_get(model, &it, MC_ID, &id, -1);
        int hit = strcmp(id, id_hex) == 0;
        g_free(id);
        if (hit) {
            gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(w->members_view)), &it);
            return;
        }
        valid = gtk_tree_model_iter_next(model, &it);
    }
}

/* 启动对话框：昵称、多播组、端口、网卡、加密、重传 */
static int start_dialog(node_config *cfg)
{
    GtkWidget *d = gtk_dialog_new_with_buttons("加入多播聊天", NULL, GTK_DIALOG_MODAL, "取消", GTK_RESPONSE_CANCEL,
                                               "加入", GTK_RESPONSE_OK, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_OK);
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 14);

    GtkWidget *name = gtk_entry_new(), *group = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(name), cfg->name);
    gtk_entry_set_activates_default(GTK_ENTRY(name), TRUE);
    gtk_entry_set_text(GTK_ENTRY(group), cfg->group);
    GtkWidget *port = gtk_spin_button_new_with_range(1024, 65535, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(port), cfg->port);
    GtkWidget *iface = gtk_combo_box_text_new_with_entry();
    char ips[16][16];
    int nips = list_local_ips(ips, 16);
    if (cfg->iface[0])
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(iface), cfg->iface);
    for (int i = 0; i < nips; i++)
        if (strcmp(ips[i], cfg->iface) != 0)
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(iface), ips[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(iface), 0);
    GtkWidget *enc = gtk_check_button_new_with_label("非对称密钥加密（RSA 分发 AES 组密钥）");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(enc), cfg->encrypt);
    GtkWidget *retr = gtk_check_button_new_with_label("文件丢包重传（NACK）");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(retr), cfg->retransmit);
    GtkWidget *tip = gtk_label_new("同一组内所有成员的组地址、端口和加密设置需一致。");
    gtk_style_context_add_class(gtk_widget_get_style_context(tip), "hint");

    const char *labels[] = {"昵称", "多播组地址", "端口", "网卡 IP"};
    GtkWidget *fields[] = {name, group, port, iface};
    for (int i = 0; i < 4; i++) {
        GtkWidget *l = gtk_label_new(labels[i]);
        gtk_label_set_xalign(GTK_LABEL(l), 1);
        gtk_grid_attach(GTK_GRID(grid), l, 0, i, 1, 1);
        gtk_widget_set_hexpand(fields[i], TRUE);
        gtk_grid_attach(GTK_GRID(grid), fields[i], 1, i, 1, 1);
    }
    gtk_grid_attach(GTK_GRID(grid), enc, 1, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), retr, 1, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), tip, 0, 6, 2, 1);
    gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(d))), grid);
    gtk_widget_show_all(d);

    int ok = 0;
    while (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) {
        const char *nm = gtk_entry_get_text(GTK_ENTRY(name)), *gp = gtk_entry_get_text(GTK_ENTRY(group));
        if (!nm[0] || !is_multicast_addr(gp)) {
            GtkWidget *m = gtk_message_dialog_new(GTK_WINDOW(d), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
                                                  !nm[0] ? "请输入昵称" : "多播组地址应在 224.0.0.0 ~ 239.255.255.255 之间");
            gtk_dialog_run(GTK_DIALOG(m));
            gtk_widget_destroy(m);
            continue;
        }
        snprintf(cfg->name, sizeof(cfg->name), "%s", nm);
        snprintf(cfg->group, sizeof(cfg->group), "%s", gp);
        cfg->port = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(port));
        char *ifc = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(iface));
        snprintf(cfg->iface, sizeof(cfg->iface), "%s", ifc ? ifc : "");
        g_free(ifc);
        cfg->encrypt = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(enc));
        cfg->retransmit = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(retr));
        ok = 1;
        break;
    }
    gtk_widget_destroy(d);
    return ok;
}

int run_gui(node_config *cfg, int name_given, int argc, char **argv)
{
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "无法打开图形显示（没有 DISPLAY？），可使用 --cli 命令行模式\n");
        return 1;
    }
    install_css();
    if (!name_given && !start_dialog(cfg))
        return 0;
    char err[256];
    gui_window *w = gui_window_create(cfg, 1, err, sizeof(err));
    if (!w) {
        GtkWidget *m = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
                                              "无法加入多播组");
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(m), "%s", err);
        gtk_dialog_run(GTK_DIALOG(m));
        gtk_widget_destroy(m);
        return 1;
    }
    gtk_main();
    return 0;
}
