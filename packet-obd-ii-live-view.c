#define BUILDING_WITH_CAN_LIVE 1
#include <stdlib.h>

#include <gtk/gtk.h>

#include <epan/funnel.h>
#include <epan/to_str.h>
#include <epan/prefs.h>

enum
{
	CAN_HIGHLIGHTER_DISABLED = 0,
	CAN_HIGHLIGHTER_TIME,
	CAN_HIGHLIGHTER_FRAMES,
};

enum
{
	CAN_COUNT_COLUMN = 0,
	CAN_LAST_FRAME_COLUMN,
	CAN_TIME,
	CAN_PERIOD_TIME,
	CAN_CAN_ID,
	CAN_RAW_VALUE_COLUMN_1,
	CAN_RAW_VALUE_COLUMN_2,
	CAN_RAW_VALUE_COLUMN_3,
	CAN_RAW_VALUE_COLUMN_4,
	CAN_RAW_VALUE_COLUMN_5,
	CAN_RAW_VALUE_COLUMN_6,
	CAN_RAW_VALUE_COLUMN_7,
	CAN_RAW_VALUE_COLUMN_8,
	CAN_PREV_FRAME_COLUMN,
	CAN_PREV_TIME,
	CAN_PTR,
	CAN_N_COLS
};

enum
{
	OBDII_PID_COLUMN = 0,
	OBDII_LAST_FRAME_COLUMN,
	OBDII_VALUE_COLUMN,
	OBDII_UNIT_COLUMN,
	OBDII_RAW_VALUE_COLUMN_A,
	OBDII_RAW_VALUE_COLUMN_B,
	OBDII_RAW_VALUE_COLUMN_C,
	OBDII_RAW_VALUE_COLUMN_D,
	OBDII_PREV_RAW_VALUE_COLUMN_A,
	OBDII_PREV_RAW_VALUE_COLUMN_B,
	OBDII_PREV_RAW_VALUE_COLUMN_C,
	OBDII_PREV_RAW_VALUE_COLUMN_D,
	OBDII_PREV_FRAME_COLUMN,
	OBDII_N_COLS
};

struct obdii_pid_info
{
	guint32 fnum, prevnum;
	gboolean ignore;

	double value;
	const char *unit;

	guint8 value_data[8];
	guint8 prev_value_data[8];
};

struct can_id_item
{
	guint32 fnum, prevnum;
	gboolean ignore, hidden;
	GtkTreeIter iter;

	guint32 can_id;
	guint32 count;
	double delta_time_start, delta_time_prev, delta_time_changed;

	guint8 value_data[8];
	guint8 prev_value_data[8];
};

struct can_live_view
{
	GtkTreeView *table;
};

static struct can_live_view can_view;
static wmem_map_t *can_ids;
static guint32 this_can_frame;
static double this_can_frame_time;

static int can_unique_len = 0;
static int can_highlighter = 100;
static int can_highlighter_type = CAN_HIGHLIGHTER_FRAMES;
static gboolean can_auto_hide = TRUE;
static gboolean can_auto_unhide = TRUE;
static guint can_auto_hide_id = 10 * 1000;

static double _can_auto_hide_ids = 0;

static struct can_live_view obdii_view;
static struct obdii_pid_info pids[256];
static guint32 this_obdii_frame;

static void
swin_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	struct can_live_view *view = (struct can_live_view *) data;

	view->table = NULL;
}

static gboolean
swindow_delete_event_cb(GtkWidget *win, GdkEvent *event _U_, gpointer user_data _U_)
{
    gtk_widget_destroy(win);
    return TRUE;
}

static void
can_live_insert_tree(GtkListStore *store, struct can_id_item *can_ptr, gboolean update_only)
{
	char buf[8][3];
	int i;

	if (update_only == FALSE)
		gtk_list_store_append(store, &can_ptr->iter);

	for (i = 0; i < 8; i++)
		*guint8_to_hex(buf[i], can_ptr->value_data[i]) = '\0';

	gtk_list_store_set(store, &can_ptr->iter,
		CAN_COUNT_COLUMN, can_ptr->count,
		CAN_LAST_FRAME_COLUMN, can_ptr->fnum,
		CAN_TIME, can_ptr->delta_time_start,
		CAN_PERIOD_TIME, can_ptr->delta_time_prev,
		CAN_CAN_ID, can_ptr->can_id,
		CAN_RAW_VALUE_COLUMN_1, buf[0],
		CAN_RAW_VALUE_COLUMN_2, buf[1],
		CAN_RAW_VALUE_COLUMN_3, buf[2],
		CAN_RAW_VALUE_COLUMN_4, buf[3],
		CAN_RAW_VALUE_COLUMN_5, buf[4],
		CAN_RAW_VALUE_COLUMN_6, buf[5],
		CAN_RAW_VALUE_COLUMN_7, buf[6],
		CAN_RAW_VALUE_COLUMN_8, buf[7],
		CAN_PREV_FRAME_COLUMN, can_ptr->prevnum,
		CAN_PREV_TIME, can_ptr->delta_time_changed,
		CAN_PTR, can_ptr,
		-1);
}

static void
can_live_remove_tree(struct can_id_item *can_ptr)
{
	if (!can_view.table)
		return;

	gtk_list_store_remove(GTK_LIST_STORE(gtk_tree_view_get_model(can_view.table)), &can_ptr->iter);
}

static void
can_live_insert_cb(gpointer key, gpointer value _U_, gpointer user_data)
{
	struct can_id_item *can_ptr = (struct can_id_item *) key;
	GtkListStore *store = (GtkListStore *) user_data;

	if (can_ptr->ignore == FALSE && can_ptr->hidden == FALSE)
		can_live_insert_tree(store, can_ptr, FALSE);
}

static void
can_live_draw_tree(void)
{
	GtkListStore *store;

	if (!can_view.table)
		return;

	/* clear list before printing */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(can_view.table));
	gtk_list_store_clear(store);

	if (can_ids)
		wmem_map_foreach(can_ids, can_live_insert_cb, store);
}

static void
obdii_live_draw(void)
{
	GtkListStore *store;
	GtkTreeIter iter;
	int element;

	if (!obdii_view.table)
		return;

	/* clear list before printing */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(obdii_view.table));
	gtk_list_store_clear(store);

	for (element = 0; element < 256; element++)
	{
		struct obdii_pid_info *pp = &pids[element];
		char bufA[4][3];
		char bufB[4][3];
		int i;

		if (!pp->fnum || pp->ignore)
			continue;

		for (i = 0; i < 4; i++)
		{
			*guint8_to_hex(bufA[i], pp->value_data[i]) = '\0';
			*guint8_to_hex(bufB[i], pp->prev_value_data[i]) = '\0';
		}

		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
			OBDII_PID_COLUMN, element,
			OBDII_LAST_FRAME_COLUMN, pp->fnum,
			OBDII_VALUE_COLUMN, pp->value,
			OBDII_UNIT_COLUMN, pp->unit,
			OBDII_RAW_VALUE_COLUMN_A, bufA[0],
			OBDII_RAW_VALUE_COLUMN_B, bufA[1],
			OBDII_RAW_VALUE_COLUMN_C, bufA[2],
			OBDII_RAW_VALUE_COLUMN_D, bufA[3],
			OBDII_PREV_RAW_VALUE_COLUMN_A, bufB[0],
			OBDII_PREV_RAW_VALUE_COLUMN_B, bufB[1],
			OBDII_PREV_RAW_VALUE_COLUMN_C, bufB[2],
			OBDII_PREV_RAW_VALUE_COLUMN_D, bufB[3],
			OBDII_PREV_FRAME_COLUMN, pp->prevnum,
			-1);
	}
}

static void
obdii_view_disable_cb(GtkCellRendererToggle *cell _U_, gchar *path, GtkListStore *model)
{
	GtkTreeIter iter;
	guint32 pid;

	gtk_tree_model_get_iter_from_string(GTK_TREE_MODEL(model), &iter, path);

	gtk_tree_model_get(GTK_TREE_MODEL(model), &iter, OBDII_PID_COLUMN, &pid, -1);
	if (pid <= 0xFF)
	{
		pids[pid].ignore = TRUE;
		obdii_live_draw();
	}
}

static void
can_view_disable_cb(GtkCellRendererToggle *cell _U_, gchar *path, GtkListStore *model)
{
	GtkTreeIter iter;
	struct can_id_item *can_ptr = NULL;

	gtk_tree_model_get_iter_from_string(GTK_TREE_MODEL(model), &iter, path);

	gtk_tree_model_get(GTK_TREE_MODEL(model), &iter, CAN_PTR, &can_ptr, -1);
	if (can_ptr)
	{
		can_ptr->ignore = TRUE;
		can_live_remove_tree(can_ptr);
	}
}

static int
can_sort_iter_compare_func(GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer userdata)
{
	int col = GPOINTER_TO_INT(userdata);
	struct can_id_item *ca = NULL;
	struct can_id_item *cb = NULL;

	gtk_tree_model_get(GTK_TREE_MODEL(model), a, CAN_PTR, &ca, -1);
	gtk_tree_model_get(GTK_TREE_MODEL(model), b, CAN_PTR, &cb, -1);

	if (!ca || !cb)
		return 0;

#define CMP_FIELD(field) \
		if (ca->field != cb->field) \
			return (ca->field > cb->field) ? 1 : -1;

	switch (col)
	{
		case CAN_COUNT_COLUMN:
			CMP_FIELD(count);
			return 0;

		case CAN_LAST_FRAME_COLUMN:
			CMP_FIELD(fnum);
			return 0;

		case CAN_TIME:
			CMP_FIELD(delta_time_start);
			return 0;

		case CAN_PERIOD_TIME:
			CMP_FIELD(delta_time_prev);
			return 0;

		case CAN_CAN_ID:
			CMP_FIELD(can_id);
			return 0;

		case CAN_PREV_FRAME_COLUMN:
			CMP_FIELD(prevnum);
			return 0;

		case CAN_PREV_TIME:
			CMP_FIELD(delta_time_changed);
			return 0;
	}

	return 0;
}

static void
can_render_id_cell_data_func(GtkTreeViewColumn *vcol _U_, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer data _U_)
{
	struct can_id_item *can_ptr = NULL;
	char id_txt[16];

	gtk_tree_model_get(model, iter, CAN_PTR, &can_ptr, -1);

	id_txt[0] = '\0';
	if (can_ptr != NULL)
		g_snprintf(id_txt, sizeof(id_txt), "%x", can_ptr->can_id);

	g_object_set(renderer, "text", id_txt, NULL);
}

static void
can_highlight_cell_data_func(GtkTreeViewColumn *vcol _U_, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	int col = GPOINTER_TO_INT(data);

	GdkColor bg_gdk;
	gboolean check = FALSE;
	unsigned int delta;

	struct can_id_item *can_ptr = NULL;

	gtk_tree_model_get(model, iter, CAN_PTR, &can_ptr, -1);
	if (can_ptr != NULL && can_highlighter_type != CAN_HIGHLIGHTER_DISABLED)
	{
		int idx = (col - CAN_RAW_VALUE_COLUMN_1);

		check = (can_ptr->value_data[idx]) != (can_ptr->prev_value_data[idx]);

		if (can_highlighter_type == CAN_HIGHLIGHTER_FRAMES)
		{
			delta = (can_ptr->fnum - can_ptr->prevnum);
		}
		else
		{
			delta = (unsigned) (1000.0 * (can_ptr->delta_time_start - can_ptr->delta_time_changed));
		}
	}

	if (check && delta < (unsigned) can_highlighter)
	{
		static const guint8 start[3] = { 0x00, 0x9C, 0xe5 };
		static const guint8 end[3]   = { 0xff, 0xff, 0xff };

		double w = ((can_highlighter - delta) / (double) can_highlighter);

		bg_gdk.red   = (guint16) (((start[0] - end[0]) * w) * 256.0);
		bg_gdk.green = (guint16) (((start[1] - end[1]) * w) * 256.0);
		bg_gdk.blue  = (guint16) (((start[2] - end[2]) * w) * 256.0);
		bg_gdk.pixel = 0;

		g_object_set(renderer,
			"background-gdk", &bg_gdk,
			"background-set", TRUE,
			NULL);
	}
	else
	{
		g_object_set(renderer,
			"background-set", FALSE,
			NULL);
	}
}

static void
obdii_highlight_cell_data_func(GtkTreeViewColumn *vcol _U_, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	int col = GPOINTER_TO_INT(data);

	GdkColor bg_gdk;
	guint32 tnum, fnum;
	gboolean check = FALSE;

	if (col >= OBDII_PREV_RAW_VALUE_COLUMN_A && col <= OBDII_PREV_RAW_VALUE_COLUMN_D)
	{
		bg_gdk.red   = 0xDDDD;
		bg_gdk.green = 0xDDDD;
		bg_gdk.blue  = 0xDDDD;
		bg_gdk.pixel = 0;

		g_object_set(renderer,
			"background-gdk", &bg_gdk,
			"background-set", TRUE,
			NULL);
		return;
	}

	if (col == OBDII_LAST_FRAME_COLUMN)
	{
		gtk_tree_model_get(model, iter, OBDII_LAST_FRAME_COLUMN, &fnum, -1);
		tnum = this_obdii_frame;
		check = TRUE;
	}
	else
	{
		guint32 pid;
		int idx = (col - OBDII_RAW_VALUE_COLUMN_A);

		gtk_tree_model_get(model, iter, OBDII_PID_COLUMN, &pid, OBDII_LAST_FRAME_COLUMN, &tnum, OBDII_PREV_FRAME_COLUMN, &fnum, -1);
		if (pid <= 0xFF)
			check = (pids[pid].value_data[idx]) != (pids[pid].prev_value_data[idx]);
	}

	if (fnum && check && tnum - fnum < 100)
	{
		static const guint8 start[3] = { 0x00, 0x9C, 0xe5 };
		static const guint8 end[3]   = { 0xff, 0xff, 0xff };

		double w = ((100 - (tnum - fnum)) / 100.0);

		bg_gdk.red   = (guint16) (((start[0] - end[0]) * w) * 256.0);
		bg_gdk.green = (guint16) (((start[1] - end[1]) * w) * 256.0);
		bg_gdk.blue  = (guint16) (((start[2] - end[2]) * w) * 256.0);
		bg_gdk.pixel = 0;

		g_object_set(renderer,
			"background-gdk", &bg_gdk,
			"background-set", TRUE,
			NULL);
	}
	else
	{
		g_object_set(renderer,
			"background-set", FALSE,
			NULL);
	}
}

static const char *
can_generate_filter(struct can_id_item *can_ptr)
{
	static char buf[256];
	char tmp[256];

	tmp[0] = '\0';
	if (can_unique_len)
	{
		char *tmp_val;

		tmp_val = bytestring_to_str(NULL, can_ptr->value_data, can_unique_len, ':');
		g_snprintf(tmp, sizeof(tmp), " && can[8:%d] == %s:", can_unique_len, tmp_val);
		wmem_free(NULL, tmp_val);
	}

	g_snprintf(buf, sizeof(buf), "(can.id == 0x%x%s)", can_ptr->can_id, tmp);

	return buf;
}

static void
can_select_node(GtkTreeSelection *selection, gpointer *user_data _U_)
{
	GtkTreeIter iter;
	GtkTreeModel *model;

	if (selection && gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		const funnel_ops_t *fops = funnel_get_funnel_ops();
		struct can_id_item *can_ptr = NULL;

		gtk_tree_model_get(model, &iter, CAN_PTR, &can_ptr, -1);
		if (can_ptr && fops && fops->set_filter)
			fops->set_filter(fops->ops_id, can_generate_filter(can_ptr));
	}
}

static void
live_show(const char *title, struct can_live_view *view)
{
	GtkListStore *store;
	const char **col_title;

	GtkWidget *scrolled_window;
	GtkWidget *win;

	if (view->table)
	{
		/* gdk_window_raise(gtk_widget_get_window(win)); */
		return;
	}

	if (view == &obdii_view)
	{
		static const char *obdii_col_title[] =
			{ "PID", "Curr. frame", "Curr. Value", "Unit", "A", "B", "C", "D", "a", "b", "c", "d", "Prev frame", NULL };

		store = gtk_list_store_new(OBDII_N_COLS,
			G_TYPE_UINT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_INT);
		col_title = obdii_col_title;
	}
	else if (view == &can_view)
	{
		static const char *can_col_title[] =
			{ "Count", "Frame No.", "Time (s)", "Period Time (s)", "CAN ID", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "Frame No. (Last change)", "Time (Last change) (s)", NULL };

		store = gtk_list_store_new(CAN_N_COLS,
			G_TYPE_UINT, G_TYPE_UINT, G_TYPE_FLOAT, G_TYPE_FLOAT, G_TYPE_UINT,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_POINTER);
		col_title = can_col_title;
	}
	else
	{
		return;
	}

	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), title);
	gtk_window_set_destroy_with_parent(GTK_WINDOW(win), TRUE);

	/* init a scrolled window*/
	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	gtk_window_set_default_size(GTK_WINDOW(win), 600, 300);

	{
		GtkWidget         *tree;
		GtkTreeViewColumn *column;
		GtkTreeSelection  *sel;
		GtkCellRenderer   *renderer;
		int i;

		tree  = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
		g_object_unref(G_OBJECT(store));

		gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(tree), FALSE);

		renderer = gtk_cell_renderer_toggle_new();
		column = gtk_tree_view_column_new_with_attributes("Hide", renderer, NULL);
		if (view == &obdii_view)
			g_signal_connect(renderer, "toggled", G_CALLBACK(obdii_view_disable_cb), store);
		else
			g_signal_connect(renderer, "toggled", G_CALLBACK(can_view_disable_cb), store);
		gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);

		for (i = 0; col_title[i]; i++)
		{
			renderer = gtk_cell_renderer_text_new();

			if (view == &can_view && i == CAN_CAN_ID)
			{
				column = gtk_tree_view_column_new_with_attributes(col_title[i], renderer, NULL);
				gtk_tree_view_column_set_cell_data_func(column, renderer, can_render_id_cell_data_func, GINT_TO_POINTER(CAN_CAN_ID), NULL);
				goto setup_done;
			}

			column = gtk_tree_view_column_new_with_attributes(col_title[i], renderer, "text", i, NULL);

			if (view == &obdii_view && (i == OBDII_LAST_FRAME_COLUMN || (i >= OBDII_RAW_VALUE_COLUMN_A && i <= OBDII_PREV_RAW_VALUE_COLUMN_D)))
				gtk_tree_view_column_set_cell_data_func(column, renderer, obdii_highlight_cell_data_func, GINT_TO_POINTER(i), NULL);
			else if (view == &can_view && (i >= CAN_RAW_VALUE_COLUMN_1 && i <= CAN_RAW_VALUE_COLUMN_8))
				gtk_tree_view_column_set_cell_data_func(column, renderer, can_highlight_cell_data_func, GINT_TO_POINTER(i), NULL);

setup_done:
			if (view == &can_view && ((i >= CAN_COUNT_COLUMN && i <= CAN_CAN_ID) || (i >= CAN_PREV_FRAME_COLUMN && i <= CAN_PREV_TIME)))
			{
				gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store), i, can_sort_iter_compare_func, GINT_TO_POINTER(i), NULL);
				gtk_tree_view_column_set_sort_column_id(column, i);
			}

			gtk_tree_view_column_set_resizable(column, TRUE);
			gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
		}

		gtk_container_add(GTK_CONTAINER(scrolled_window), GTK_WIDGET(tree));
		gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(tree), TRUE);
		sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
		gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);

		if (view == &can_view)
			g_signal_connect(G_OBJECT(sel), "changed", G_CALLBACK(can_select_node), NULL);

		gtk_widget_show(tree);

		view->table = GTK_TREE_VIEW(tree);
	}

	gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(scrolled_window));
	gtk_widget_show(scrolled_window);

	g_signal_connect(win, "delete_event", G_CALLBACK(swindow_delete_event_cb), NULL);
	g_signal_connect(win, "destroy", G_CALLBACK(swin_destroy_cb), view);

	gtk_widget_show_all(win);
	gtk_window_present(GTK_WINDOW(win));

	gdk_window_raise(gtk_widget_get_window(win));
}

static gint
live_can_id_equal(gconstpointer k1, gconstpointer k2)
{
	const struct can_id_item *key1 = (const struct can_id_item *) k1;
	const struct can_id_item *key2 = (const struct can_id_item *) k2;

	if (key1->can_id != key2->can_id)
		return FALSE;

	if (can_unique_len && memcmp(key1->value_data, key2->value_data, can_unique_len) != 0)
		return FALSE;

	return TRUE;
}

static guint
live_can_id_hash(gconstpointer k)
{
	const struct can_id_item *key = (const struct can_id_item *) k;
	guint hashkey;

	hashkey = key->can_id;
	if (can_unique_len)
		hashkey ^= wmem_strong_hash(key->value_data, can_unique_len);

	return hashkey;
}

static void
can_live_clean(void)
{
	if (can_ids)
	{
		/* clear tree, and store */
		can_ids = wmem_map_new(wmem_epan_scope(), live_can_id_hash, live_can_id_equal);
		can_live_draw_tree();
	}
}

static void
can_live_unhide_cb(gpointer key, gpointer value _U_, gpointer user_data _U_)
{
	struct can_id_item *can_ptr = (struct can_id_item *) key;

	can_ptr->ignore = FALSE;
}

static void
can_live_show(void *data _U_)
{
	live_show("CAN Live IDs", &can_view);
	wmem_map_foreach(can_ids, can_live_unhide_cb, NULL);
	can_live_draw_tree();
}

static void
obdii_live_show(void *data _U_)
{
	int i;

	live_show("OBD-II PIDs", &obdii_view);
	for (i = 0; i <= 0xFF; i++)
		pids[i].ignore = FALSE;
	obdii_live_draw();
}

static void
obdii_live_update(const struct obdii_info_tap *obdii_info, const struct obdii_packet_info *oinfo)
{
	struct obdii_pid_info *pp = &pids[obdii_info->pid];
	guint8 value_data[4];

	memset(value_data, 0, sizeof(value_data));
	this_obdii_frame = oinfo->pinfo->fd->num;

	if (oinfo->value_bytes >= 1) value_data[0] = oinfo->valueA;
	if (oinfo->value_bytes >= 2) value_data[1] = oinfo->valueB;
	if (oinfo->value_bytes >= 3) value_data[2] = oinfo->valueC;
	if (oinfo->value_bytes >= 4) value_data[3] = oinfo->valueD;

	if (memcmp(value_data, pp->value_data, 4) != 0)
	{
		pp->prevnum = pp->fnum;
		memcpy(pp->prev_value_data, pp->value_data, 4);
	}

	pp->fnum = oinfo->pinfo->fd->num;
	pp->value = obdii_info->value;
	pp->unit  = obdii_info->unit;
	memcpy(pp->value_data, value_data, 4);

	obdii_live_draw();
}

static void
can_live_autohide_cb(gpointer key, gpointer value _U_, gpointer user_data _U_)
{
	struct can_id_item *can_ptr = (struct can_id_item *) key;

	if (can_ptr->hidden == FALSE && can_ptr->ignore == FALSE && (this_can_frame_time - can_ptr->delta_time_changed) >= _can_auto_hide_ids)
	{
		can_ptr->hidden = TRUE;
		can_live_remove_tree(can_ptr);
	}
}

static void
can_live_insert(guint32 can_id, tvbuff_t *tvb, packet_info *pinfo)
{
	struct can_id_item tmp_key;

	struct can_id_item *can_ptr;
	int tvb_length;

	double this_time;
	gboolean update_only = TRUE;

	if (can_ids == NULL)
		can_ids = wmem_map_new(wmem_epan_scope(), live_can_id_hash, live_can_id_equal);

	tvb_length = tvb_reported_length(tvb);

	tmp_key.can_id = can_id;
	tvb_memcpy(tvb, tmp_key.value_data, 0, MIN(tvb_length, 8));

	can_ptr = (struct can_id_item *) wmem_map_lookup(can_ids, &tmp_key);

	this_can_frame_time = this_time = nstime_to_sec(&pinfo->rel_ts);

	if (!can_ptr)
	{
		update_only = FALSE;

		can_ptr = wmem_new0(wmem_file_scope(), struct can_id_item);

		can_ptr->can_id = can_id;
		can_ptr->delta_time_changed = this_time;
		memcpy(can_ptr->value_data, tmp_key.value_data, 8);

		wmem_map_insert(can_ids, can_ptr, can_ptr);
	}
	else
	{
		if (memcmp(tmp_key.value_data, can_ptr->value_data, 8) != 0)
		{
			can_ptr->prevnum = can_ptr->fnum;
			memcpy(can_ptr->prev_value_data, can_ptr->value_data, 8);

			can_ptr->delta_time_changed = this_time;
		}

		memcpy(can_ptr->value_data, tmp_key.value_data, 8);

		/* delta time prev always update */
		can_ptr->delta_time_prev = (this_time - can_ptr->delta_time_start);
	}

	_can_auto_hide_ids = can_auto_hide_id / 1000.0;

	can_ptr->count = can_ptr->count + 1;

	can_ptr->fnum = pinfo->fd->num;
	can_ptr->delta_time_start = this_time;

	if (can_auto_unhide && can_ptr->hidden == TRUE && (this_can_frame_time - can_ptr->delta_time_changed) < _can_auto_hide_ids)
	{
		update_only = FALSE;
		can_ptr->hidden = FALSE;
	}

	if (can_view.table)
	{
		if (can_ptr->ignore == FALSE && can_ptr->hidden == FALSE)
			can_live_insert_tree(GTK_LIST_STORE(gtk_tree_view_get_model(can_view.table)), can_ptr, update_only);
	}

	this_can_frame = pinfo->fd->num;
	if (can_auto_hide && _can_auto_hide_ids > 0.0)
	{
		/* TODO, optimize O(N) */
		wmem_map_foreach(can_ids, can_live_autohide_cb, NULL);
	}
}

static void
live_init(void)
{
	static const enum_val_t can_highlighter_vals[] =
	{
		{ "off",    "Disabled",  CAN_HIGHLIGHTER_DISABLED },
		{ "time",   "Time (ms)", CAN_HIGHLIGHTER_TIME },
		{ "frames", "Frames",    CAN_HIGHLIGHTER_FRAMES },
		{ NULL,     NULL,        -1 }
	};

	const funnel_ops_t *fops;

	module_t *live_module = prefs_register_stat("can_live", "CAN Live", "CAN Live", NULL);

	prefs_register_uint_preference(live_module, "unique_len", "Data bytes to include in ID", "Data bytes to include in ID", 10, &can_unique_len);

	prefs_register_enum_preference(live_module, "highlighter_type", "Highlight type", "Change highlight type", &can_highlighter_type, can_highlighter_vals, TRUE);
	prefs_register_uint_preference(live_module, "highlighter", "Highlighter decay rate", "Change highlighter decay rate", 10, &can_highlighter);

	prefs_register_bool_preference(live_module, "auto_hide", "Automatically hide IDs with no change", "Automatically hide IDs with no change", &can_auto_hide);
	prefs_register_uint_preference(live_module, "auto_hide_msecs", "Automatically hide IDs with no change (ms)", "Automatically hide IDs with no change (ms)", 10, &can_auto_hide_id);
	prefs_register_bool_preference(live_module, "auto_unhide", "Automatically unhide IDs after change", "Automatically unhide IDs after change", &can_auto_unhide);
	prefs_register_static_text_preference(live_module, "advert_note", "This plugin has been developed for CSS Electronics and is available for free. For more info on the plugin and our CAN bus data loggers, please check out www.csselectronics.com", "This plugin has been developed for CSS Electronics and is available for free. For more info on the plugin and our CAN bus data loggers, please check out www.csselectronics.com");

	fops = funnel_get_funnel_ops();
	if (fops && fops->ops_id == NULL) /* gtk check, XXX can be it checked better without using GTK wireshark internal implementation? */
	{
		funnel_register_menu("CAN Live IDs", REGISTER_STAT_GROUP_UNSORTED, can_live_show, NULL, FALSE);
		funnel_register_menu("OBD-II Live PIDs", REGISTER_STAT_GROUP_UNSORTED, obdii_live_show, NULL, FALSE);
	}
	register_cleanup_routine(can_live_clean);
}
