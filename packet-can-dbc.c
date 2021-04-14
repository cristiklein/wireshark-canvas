/* packet-can-dbc.c
 * Routines for CAN DBC dissection
 * Copyright 2017, Jakub Zawadzki for CSS Electronics <www.csselectronics.com>
 *
 * Based on https://www.infineonforums.com/threads/1166-Generating-C-Code-from-Vector-CANdb-.dbc-files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/uat.h>
#include <epan/expert.h>

#include <wiretap/wtap-int.h>

#include <wsutil/sign_ext.h>
#include <wsutil/file_util.h>
#include <wsutil/strtoi.h>

void proto_register_dbc(void);
void proto_reg_handoff_dbc(void);

#define DBC_SIGNAL_MOTOROLA (1 << 0)
#define DBC_SIGNAL_INTEL    (0 << 0)
#define DBC_SIGNAL_UNSIGNED (1 << 1)
#define DBC_SIGNAL_SIGNED   (0 << 1)
#define DBC_SIGNAL_JUST_BIT (1 << 2)

struct dbc_file
{
	char *path;
	unsigned int ftype;
};

struct dbc_signal
{
	struct dbc_signal *next;

	char *name;
	char *comment;

	guint8 bit_start;
	guint8 bit_length;
	guint8 flags;

	double factor;
	double offset;
	double min_value;
	double max_value;
	char *unit;
	value_string *vals;

	int hf_id;
	int ett_id;
};

struct dbc_message
{
	const struct dbc_file *file;

	guint32 orig_id;
	guint32 id;
	char *name;
	char *comment;

	int hf_id;
	int ett_id;
	struct dbc_signal *signals;
	unsigned int signal_count;
};

struct dbc_context
{
	const struct dbc_file *file;
	FILE *fp;
	char buf[4096];

	guint32 msg_id_mask;

	struct dbc_message *current_msg;
};

#define DBC_FILE_TYPE_GENERAL 0
#define DBC_FILE_TYPE_J1939   1

struct dbc_files_uat_data
{
	char *filename;
	unsigned int ftype;
};

static const value_string dbc_files_type_vals[] =
{
	{ DBC_FILE_TYPE_GENERAL, "General" },
	{ DBC_FILE_TYPE_J1939, "J1939 (CAN ID masked 0x03FFFF00)" },
	{ 0, NULL }
};

static gboolean dbc_multi_row = FALSE;
static gboolean dbc_multi_row_active = FALSE;
static struct dbc_files_uat_data *dbc_files_uat_data = NULL;
static guint num_dbc_files_uat_data = 0;

static GHashTable *dbc_msg_ids;

static int proto_dbc = -1;
static int ett_dbc = -1;

#define MAX_SIGNAL 127

static int hf_dbc_module_name = -1;
static int hf_dbc_frame_num = -1;
static int hf_dbc_message_id = -1;
static int hf_dbc_message_orig_id = -1;
static int hf_dbc_message_name = -1;
static int hf_dbc_message_comment = -1;
static int hf_dbc_signal_name[MAX_SIGNAL];
static int hf_dbc_signal_comment[MAX_SIGNAL];
static int hf_dbc_signal_val[MAX_SIGNAL];
static int hf_dbc_signal_val_min[MAX_SIGNAL];
static int hf_dbc_signal_val_max[MAX_SIGNAL];
static int hf_dbc_signal_unit[MAX_SIGNAL];

static expert_field ei_dbc_signal_max = EI_INIT;
static expert_field ei_dbc_signal_min = EI_INIT;

/* Parser */

static size_t
dbc_skip_sepa(const char **pmsg)
{
	const char *msg = *pmsg;
	size_t pos = 0;

	while (g_ascii_isspace(msg[pos]))
		pos++;

	*pmsg = &(msg[pos]);
	return pos;
}

static gboolean
dbc_skip_char(const char **pmsg, char ch)
{
	const char *msg = *pmsg;
	gboolean ret = FALSE;

	if (*msg == ch)
	{
		msg++;
		ret = TRUE;
	}

	*pmsg = msg;
	return ret;
}

static char *
dbc_parse_str(const char **pmsg)
{
	GString *str;

	const char *msg = *pmsg;
	size_t pos;

	pos = 0;

	if (msg[pos] != '"')
		return NULL;

	pos++;

	str = g_string_new("");

	while (msg[pos] && msg[pos] != '"')
	{
		g_string_append_c(str, msg[pos]);
		pos++;
	}

	if (msg[pos] == '\0')
	{
		/* TODO, string can be over multiple lines */
	}

	if (msg[pos] != '"')
	{
		g_string_free(str, TRUE);
		return NULL;
	}

	*pmsg = &(msg[pos + 1]);
	return g_string_free(str, FALSE);
}

static char *
dbc_parse_name(const char **pmsg)
{
	const char *msg = *pmsg;
	size_t pos = 0;

	if (!g_ascii_isalpha(msg[pos]) || msg[pos] == '_')
		return NULL;
	pos++;

	while (g_ascii_isalnum(msg[pos]) || msg[pos] == '_')
		pos++;

	*pmsg = &(msg[pos]);
	return g_strndup(msg, pos);
}

static gboolean
dbc_parse_num(const char **pmsg, double *val)
{
	const char *msg = *pmsg;

	*val = g_ascii_strtod(msg, (char **) &msg);

	if (msg == *pmsg)
		return FALSE;

	*pmsg = msg;
	return TRUE;
}

#define DBC_PARSER_ORIG 2
#define DBC_PARSER_NOT_SUPPORTED 1
#define DBC_PARSER_INFO 0
#define DBC_PARSER_FAIL -1
#define DBC_PARSER_WRONG -2
#define DBC_PARSER_SANITY -3
#define DBC_PARSER_UNKNOWN -4

static void
dbc_parse_debug(int num, const char *format, ...)
{
#if 0
	va_list ap;

	if (num >= DBC_PARSER_INFO)
		return;
{
FILE *fp = fopen("C:/Development/dbg", "a");
	va_start(ap, format);
	vfprintf(fp, format, ap);
	va_end(ap);
fclose(fp);
}
#endif
}

static int
dbc_parse_msg(struct dbc_context *ctx, const char *msg)
{
	/* BO_ <MSG_ID> <MSG_NAME>: <DLC_VAL> <ECU_VAL> */
	guint32 orig_msg_id;
	guint32 msg_id;
	char *msg_name = NULL;
	guint32 dlc_val;
	char *ecu_val = NULL;

	struct dbc_message *message;

	ctx->current_msg = NULL;

	/* ID */
	if (!ws_strtou32(msg, &msg, &msg_id) || !dbc_skip_sepa(&msg))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing message id failed.\n");
		return -1;
	}

	orig_msg_id = msg_id;
	msg_id = msg_id & ctx->msg_id_mask;

	message = (struct dbc_message *) g_hash_table_lookup(dbc_msg_ids, GUINT_TO_POINTER(msg_id));
	if (message)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: message ID %u already defined by %s\n", msg_id, message->name);
		return -2;
	}

	/* Name */
	msg_name = dbc_parse_name(&msg);
	if (!msg_name)
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing message name failed.\n");
		goto fail;
	}
	dbc_skip_sepa(&msg);

	/* sepa */
	if (!dbc_skip_char(&msg, ':'))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing message, ':' not found\n");
		goto fail;
	}

	dbc_skip_sepa(&msg);

	/* DLC */
	if (!ws_strtou32(msg, &msg, &dlc_val) || !dbc_skip_sepa(&msg))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing message dlc failed.\n");
		goto fail;
	}

	/* ECU */
	ecu_val = dbc_parse_name(&msg);
	if (!ecu_val)
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing ECU failed.\n");
		goto fail;
	}

	dbc_parse_debug(DBC_PARSER_ORIG, "BO_ %u %s: %u %s\n", msg_id, msg_name, dlc_val, ecu_val);
/*	fprintf(stderr, "dbc: new message (ID: %u) (NAME: %s) (DLC: %u) (ECU: %s) (LEFT: %s)\n", msg_id, msg_name, dlc_val, ecu_val, msg); */

	message = g_new0(struct dbc_message, 1);
	message->id = msg_id;
	message->orig_id = orig_msg_id;
	message->name = msg_name;
	(void) dlc_val;  /* skipped */
	g_free(ecu_val); /* skipped */

	message->file = ctx->file;
	message->signals = NULL;
	message->hf_id  = -1;
	message->ett_id = -1;

	g_hash_table_insert(dbc_msg_ids, GUINT_TO_POINTER(msg_id), message);
	ctx->current_msg = message;

	return 0;

fail:
	g_free(msg_name);
	g_free(ecu_val);
	return -1;
}

static int
dbc_parse_msg_comment(struct dbc_context *ctx, const char *cmt)
{
	guint32 msg_id;
	struct dbc_message *message;

	dbc_skip_sepa(&cmt);

	if (!ws_strtou32(cmt, &cmt, &msg_id) || !dbc_skip_sepa(&cmt))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing message comment id failed.\n");
		return -1;
	}

	msg_id = msg_id & ctx->msg_id_mask;

	message = (struct dbc_message *) g_hash_table_lookup(dbc_msg_ids, GUINT_TO_POINTER(msg_id));
	if (!message)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: parsing message comment, ID %u not defined?\n", msg_id);
		return -2;
	}

	if (message->comment)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: message comment for ID %u already defined\n", msg_id);
		return -2;
	}

	message->comment = dbc_parse_str(&cmt);

	dbc_parse_debug(DBC_PARSER_ORIG, "CM_ BO_ %u \"%s\"\n", msg_id, message->comment);

	return 0;
}

static int
dbc_parse_sig_comment(struct dbc_context *ctx, const char *cmt)
{
	guint32 msg_id;
	char *sig_name = NULL;

	struct dbc_message *message;
	struct dbc_signal *signall;

	dbc_skip_sepa(&cmt);

	if (!ws_strtou32(cmt, &cmt, &msg_id) || !dbc_skip_sepa(&cmt))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal comment id failed.\n");
		return -1;
	}

	msg_id = msg_id & ctx->msg_id_mask;

	message = (struct dbc_message *) g_hash_table_lookup(dbc_msg_ids, GUINT_TO_POINTER(msg_id));
	if (!message)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: parsing signal comment, ID %u not defined?\n", msg_id);
		return -2;
	}

	/* Name */
	sig_name = dbc_parse_name(&cmt);
	if (!sig_name)
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal comment, name failed.\n");
		return -1;
	}

	dbc_skip_sepa(&cmt);

	for (signall = message->signals; signall; signall = signall->next)
	{
		if (!strcmp(signall->name, sig_name))
			break;
	}

	if (!signall)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: parsing signal comment, ID %u, name %s not defined?\n", msg_id, sig_name);
		g_free(sig_name);
		return -2;
	}

	if (signall)
	{
		if (!signall->comment)
		{
			signall->comment = dbc_parse_str(&cmt);
			dbc_parse_debug(DBC_PARSER_ORIG, "CM_ SG_ %u %s \"%s\"\n", msg_id, sig_name, signall->comment);
		}
		else
		{
			dbc_parse_debug(DBC_PARSER_FAIL, "dbc: message comment for ID %u, name %s already defined\n", msg_id, sig_name);
		}
	}

	g_free(sig_name);
	return 0;
}

static int
dbc_parse_sig(struct dbc_context *ctx, const char *sig)
{
	struct dbc_signal *signall;
	struct dbc_signal *signall_ins = NULL;
	struct dbc_message *message = ctx->current_msg;

	char *sig_name = NULL;
	guint32 sig_bit_start, sig_bit_length;
	guint8 sig_flags = 0;
	double sig_fac, sig_off;
	double sig_min, sig_max;
	char *sig_unit = NULL;

	/* SG_ <SIG_NAME> [MULTIPLEX] : <BYTE_ENCODING> <FAC_OFF> [0|2000] "kPa" Vector__XXX */

	if (message == NULL)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: signal definition outside message? '%s'\n", sig);
		return -2;
	}

	dbc_skip_sepa(&sig);

	/* Name */
	sig_name = dbc_parse_name(&sig);
	if (!sig_name)
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal name failed.\n");
		goto fail;
	}

	dbc_skip_sepa(&sig);

	/* Multiplex */
	if (dbc_skip_char(&sig, 'M'))
	{

	}
	else if (dbc_skip_char(&sig, 'm'))
	{
		guint32 val;

		ws_strtou32(sig, &sig, &val);
	}

	dbc_skip_sepa(&sig);

	/* sepa */
	if (!dbc_skip_char(&sig, ':'))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, sig: '%s'\n", sig);
		goto fail;
	}
	dbc_skip_sepa(&sig);

	/* Byte Encoding */
	if (!ws_strtou32(sig, &sig, &sig_bit_start))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, expected <bit_start>, sig: '%s'\n", sig);
		goto fail;
	}

	dbc_skip_sepa(&sig);
	if (!dbc_skip_char(&sig, '|'))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, expected '|', sig: '%s'\n", sig);
		goto fail;
	}

	if (!ws_strtou32(sig, &sig, &sig_bit_length))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, expected <bit_len>, sig: '%s'\n", sig);
		goto fail;
	}

	if (!dbc_skip_char(&sig, '@'))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, expected '@', sig: '%s'\n", sig);
		goto fail;
	}

	if (dbc_skip_char(&sig, '0'))
		sig_flags |= DBC_SIGNAL_MOTOROLA;
	else if (dbc_skip_char(&sig, '1'))
		sig_flags |= DBC_SIGNAL_INTEL;
	else
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, expected 0/1, sig: '%s'\n", sig);
		goto fail;
	}

	if (dbc_skip_char(&sig, '+'))
		sig_flags |= DBC_SIGNAL_UNSIGNED;
	else if (dbc_skip_char(&sig, '-'))
		sig_flags |= DBC_SIGNAL_SIGNED;
	else
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal failed, expected +/-, sig: '%s'\n", sig);
		goto fail;
	}
	dbc_skip_sepa(&sig);

	/* Factor and offset */
	if (!dbc_skip_char(&sig, '(') ||
		!dbc_parse_num(&sig, &sig_fac) ||
		!dbc_skip_char(&sig, ',') ||
		!dbc_parse_num(&sig, &sig_off) ||
		!dbc_skip_char(&sig, ')') ||
		!dbc_skip_sepa(&sig))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing <sig_fac> failed.\n");
		goto fail;
	}

	if (sig_off == 0.0 && sig_fac == 1.0)
		sig_flags |= DBC_SIGNAL_JUST_BIT;

	/* Min and Max */
	if (!dbc_skip_char(&sig, '[') ||
		!dbc_parse_num(&sig, &sig_min) ||
		!dbc_skip_char(&sig, '|') ||
		!dbc_parse_num(&sig, &sig_max) ||
		!dbc_skip_char(&sig, ']') ||
		!dbc_skip_sepa(&sig))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing <min_max> failed.\n");
		goto fail;
	}

	sig_unit = dbc_parse_str(&sig);

	/* TODO */

	if (sig_bit_start > 64 || sig_bit_length > 64 || sig_bit_start + sig_bit_length > 64)
	{
		dbc_parse_debug(DBC_PARSER_SANITY, "dbc: signal sanity for <%s>.%s. Bit start > 64 [%u] or length > 64 [%u] or total > 64 [%u]\n", message->name, sig_name, sig_bit_start, sig_bit_length, sig_bit_start + sig_bit_length);
	}

	dbc_parse_debug(DBC_PARSER_ORIG, " SG_ %s : %u|%u@%c%c (%g,%g) [%g|%g] %s\n",
			sig_name, sig_bit_start, sig_bit_length,
			(sig_flags & DBC_SIGNAL_MOTOROLA) ? '0' : '1',
			(sig_flags & DBC_SIGNAL_UNSIGNED) ? '+' : '-',
			sig_fac, sig_off, sig_min, sig_max, sig_unit);
	// fprintf(stderr, "dbc: new signal (message name: %s) (NAME: %s) (ENC: %d...%d %.1x) (FAC: %f) (OFF: %f) (VAL: %f ... %f) (UNIT: %s)\n", message->name, sig_name, sig_bit_start, sig_bit_length, sig_flags, sig_fac, sig_off, sig_min, sig_max, sig_unit);

	for (signall = message->signals; signall; signall = signall->next)
	{
		/* sort by bit start */
		if (sig_bit_start > signall->bit_start)
			signall_ins = signall;

		if (!strcmp(signall->name, sig_name))
		{
			dbc_parse_debug(DBC_PARSER_WRONG, "dbc: signal %s for message %s already defined\n", sig_name, message->name);
			goto fail;
		}
	}

	signall = g_new0(struct dbc_signal, 1);
	signall->name = sig_name;
	signall->bit_start  = sig_bit_start;
	signall->bit_length = sig_bit_length;
	signall->factor     = sig_fac;
	signall->offset     = sig_off;
	signall->min_value  = sig_min;
	signall->max_value  = sig_max;
	signall->flags      = sig_flags;
	signall->unit       = sig_unit;

	signall->hf_id = -1;
	signall->ett_id = -1;

	message->signal_count++;
	if (signall_ins)
	{
		signall->next = signall_ins->next;
		signall_ins->next = signall;
	}
	else
	{
		signall->next = message->signals;
		message->signals = signall;
	}

	return 0;
fail:
	g_free(sig_name);
	g_free(sig_unit);
	return -1;
}

static int
dbc_parse_sig_enum(struct dbc_context *ctx, const char *sig_enum)
{
	struct dbc_message *message;
	struct dbc_signal *signall;

	guint32 msg_id;
	char *sig_name = NULL;

	GArray *vals;
	value_string val;

	dbc_skip_sepa(&sig_enum);

	if (!ws_strtou32(sig_enum, &sig_enum, &msg_id) || !dbc_skip_sepa(&sig_enum))
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal enum id failed.\n");
		return -1;
	}

	msg_id = msg_id & ctx->msg_id_mask;

	message = (struct dbc_message *) g_hash_table_lookup(dbc_msg_ids, GUINT_TO_POINTER(msg_id));
	if (!message)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: parsing signal enum, ID %u not defined?\n", msg_id);
		return -2;
	}

	/* Name */
	sig_name = dbc_parse_name(&sig_enum);
	if (!sig_name)
	{
		dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal enum, name failed.\n");
		return -1;
	}

	dbc_skip_sepa(&sig_enum);

	for (signall = message->signals; signall; signall = signall->next)
	{
		if (!strcmp(signall->name, sig_name))
			break;
	}

	if (!signall)
	{
		dbc_parse_debug(DBC_PARSER_WRONG, "dbc: parsing signal enum, ID %u, name %s not defined?\n", msg_id, sig_name);
		g_free(sig_name);
		return -2;
	}

	g_free(sig_name);
	sig_name = signall->name;

	if ((signall->flags & DBC_SIGNAL_JUST_BIT) == 0)
	{
		dbc_parse_debug(DBC_PARSER_SANITY, "dbc: sanity signal enum %s not DBC_SIGNAL_JUST_BIT\n", sig_name);
		return -2;
	}

	vals = g_array_new(FALSE, FALSE, sizeof(value_string));

	while (*sig_enum && *sig_enum != ';')
	{
		if (!ws_strtou32(sig_enum, &sig_enum, &val.value) || !dbc_skip_sepa(&sig_enum))
		{
			dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal %s enum val-id failed\n", sig_enum);
			return -1;
		}

		val.strptr = dbc_parse_str(&sig_enum);
		if (!val.strptr)
		{
			dbc_parse_debug(DBC_PARSER_FAIL, "dbc: parsing signal %s enum, val-str failed\n", sig_name);
			return -1;
		}

		dbc_skip_sepa(&sig_enum);

		g_array_append_vals(vals, &val, 1);
	}

	val.value = 0;
	val.strptr = NULL;
	g_array_append_vals(vals, &val, 1);

	signall->vals = (value_string *) g_array_free(vals, FALSE);

	return 0;
}

static int
dbc_parse_line(struct dbc_context *ctx, const char *line)
{
	if (!strncmp(line, "BO_ ", 4))
	{
		line += 4;
		return dbc_parse_msg(ctx, line);
	}

	if (!strncmp(line, "SG_ ", 4))
	{
		line += 4;
		return dbc_parse_sig(ctx, line);
	}

	if (!strncmp(line, "VAL_ ", 5))
	{
		line += 5;
		return dbc_parse_sig_enum(ctx, line);
	}

	if (!strncmp(line, "CM_ BO_ ", 8))
	{
		line += 8;
		return dbc_parse_msg_comment(ctx, line);
	}

	if (!strncmp(line, "CM_ SG_ ", 8))
	{
		line += 8;
		return dbc_parse_sig_comment(ctx, line);
	}

	if (!strncmp(line, "BA_ ", 4))
	{
		dbc_parse_debug(DBC_PARSER_NOT_SUPPORTED, "dbc: BA_ not supported: %s\n", line);
		return -1;
	}

	dbc_parse_debug(DBC_PARSER_UNKNOWN, "<?> %s\n", line);

	return -1;
}

static char *
dbc_fgets(struct dbc_context *ctx)
{
	if ((fgets(ctx->buf, sizeof(ctx->buf), ctx->fp)))
	{
		char *ptr = ctx->buf;
		size_t len;

		dbc_skip_sepa((const char **) &ptr);

		len = strlen(ptr);

		if (len > 0 && g_ascii_isspace(ptr[len - 1]))
			len--;

		ptr[len] = '\0';

		return ptr;
	}

	return NULL;
}

static int
dbc_read_file(const char *path, int ftype, guint32 mask)
{
	struct dbc_context ctx;
	struct dbc_file *ctx_f;

	char *buf;

	FILE *fp = fopen(path, "rb");
	if (!fp)
		return -1;

	ctx_f = g_new0(struct dbc_file, 1);
	ctx_f->path = g_strdup(path);
	ctx_f->ftype = ftype;

	memset(&ctx, 0, sizeof(ctx));
	ctx.msg_id_mask = mask;
	ctx.file = ctx_f;
	ctx.fp   = fp;

	while ((buf = dbc_fgets(&ctx)))
	{
		if (buf[0] == '\0')
			continue;

		dbc_parse_line(&ctx, buf);
	}

	return 0;
}

/* Dissect */

static struct dbc_message *
dbc_message_lookup(guint32 can_id)
{
	struct dbc_message *message;

	message = (struct dbc_message *) g_hash_table_lookup(dbc_msg_ids, GUINT_TO_POINTER(can_id));
	if (message)
		return message;

	/* try J1939 variant */
	can_id = (can_id & 0x03FFFF00);
	message = (struct dbc_message *) g_hash_table_lookup(dbc_msg_ids, GUINT_TO_POINTER(can_id));
	if (message && message->id != message->orig_id)
		return message;

	return NULL;
}

static inline guint64
dbc_extract_bits(tvbuff_t *tvb, unsigned int bpos, unsigned int align, unsigned int shifter, unsigned int pos)
{
	guint64 val = tvb_get_guint8(tvb, bpos / 8);

	unsigned int mask = (1 << shifter) - 1;

	return ((val >> align) & mask) << pos;
}

static guint64
dbc_extract_bits_intel(tvbuff_t *tvb, unsigned int bpos, unsigned int bits)
{
	unsigned int pos, aligner, shifter;
	guint64 val = 0;

	pos = 0;
	while (bits > 0)
	{
		aligner = bpos % 8;
		shifter = 8 - aligner;
		shifter = MIN(shifter, bits);

		val |= dbc_extract_bits(tvb, bpos, aligner, shifter, pos);
		pos += shifter;

		bpos += shifter;
		bits -= shifter;
	}

	return val;
}

static guint64
dbc_extract_bits_motorola(tvbuff_t *tvb, unsigned int bpos, unsigned int bits)
{
	unsigned int pos, aligner, slicer;
	guint64 val = 0;

	pos = bits;
	while (bits > 0)
	{
		slicer = (bpos % 8) + 1;
		slicer = MIN(slicer, bits);
		aligner = ((bpos % 8) + 1) - slicer;

		pos -= slicer;
		val |= dbc_extract_bits(tvb, bpos, aligner, slicer, pos);

		bpos = ((bpos / 8) + 1) * 8 + 7;
		bits -= slicer;
	}

	return val;
}

static void
dissect_dbc_message_signal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct dbc_signal *signall, int sig_number)
{
	double val;
	guint64 bits_val;
	proto_item *ti;
	proto_tree *sig_tree;

	const char *s_unit = signall->unit;
	const char *s_vals = "";

	bits_val = (signall->flags & DBC_SIGNAL_MOTOROLA) ?
			dbc_extract_bits_motorola(tvb, signall->bit_start, signall->bit_length) :
			dbc_extract_bits_intel(tvb, signall->bit_start, signall->bit_length);

	if ((signall->flags & DBC_SIGNAL_UNSIGNED) == 0)
	{
		bits_val = ws_sign_ext64(bits_val, signall->bit_length);
		val = signall->offset + signall->factor * ((gint64) bits_val);
	}
	else
	{
		val = signall->offset + signall->factor * bits_val;
	}

	if (signall->flags & DBC_SIGNAL_JUST_BIT)
	{
		if (signall->bit_length > 32)
		{
			if (signall->flags & DBC_SIGNAL_UNSIGNED)
				ti = proto_tree_add_uint64(tree, signall->hf_id, tvb, 0, 8, bits_val);
			else
				ti = proto_tree_add_int64(tree, signall->hf_id, tvb, 0, 8, (gint64) bits_val);
		}
		else
		{
			if (signall->flags & DBC_SIGNAL_UNSIGNED)
				ti = proto_tree_add_uint(tree, signall->hf_id, tvb, 0, 8, (unsigned) bits_val);
			else
				ti = proto_tree_add_int(tree, signall->hf_id, tvb, 0, 8, (int) bits_val);
		}

		if (signall->vals && (bits_val >> 32) == 0)
			s_vals = val_to_str_const((guint32) bits_val, signall->vals, "");
	}
	else
		ti = proto_tree_add_double(tree, signall->hf_id, tvb, 0, 8, val);

	if (dbc_multi_row && dbc_multi_row_active)
		sig_tree = tree;
	else
		sig_tree = proto_item_add_subtree(ti, signall->ett_id);
    
	if (val < signall->min_value)
		proto_tree_add_expert_format(sig_tree, pinfo, &ei_dbc_signal_min, tvb, 0, 8, "WARNING: value (%g) is below MIN (%g)", val, signall->min_value);

	if (val > signall->max_value)
		proto_tree_add_expert_format(sig_tree, pinfo, &ei_dbc_signal_max, tvb, 0, 8, "WARNING: value (%g) is above MAX (%g)", val, signall->max_value);

	{
		gint bytes = tvb_captured_length(tvb);
		const guint8 *cp = tvb_get_ptr(tvb, 0, bytes);

		/* should be <= 8, but allow more... */
		if (bytes > 16)
			bytes = 16;

		if (bytes > 0)
		{
			char bits_str[16 * 8 + 1];
			gint bits = bytes * 8;
			int i;

			memset(bits_str, '.', bits);
			bits_str[bits] = '\0';
			for (i = signall->bit_start; i < bits && i < signall->bit_start + signall->bit_length; i++)
				bits_str[(bits - 1) - i] = (cp[i / 8] & (1 << (i % 8))) ? '1' : '0';

			proto_item_prepend_text(ti, "%s = ", bits_str);
		}
	}

	if (!s_unit)
		s_unit = "";

	if ((signall->flags & DBC_SIGNAL_UNSIGNED) == 0)
		proto_item_append_text(ti, "%s (%g + %g * %" G_GINT64_FORMAT ")", s_unit, signall->offset, signall->factor, bits_val);
	else
		proto_item_append_text(ti, "%s (%g + %g * %" G_GUINT64_FORMAT ")", s_unit, signall->offset, signall->factor, bits_val);

	if (sig_number < MAX_SIGNAL)
	{
		proto_tree_add_string(sig_tree, hf_dbc_signal_name[sig_number], tvb, 0, 8, signall->name);
		if (signall->comment)
			proto_tree_add_string(sig_tree, hf_dbc_signal_comment[sig_number], tvb, 0, 8, signall->comment);
		proto_tree_add_double(sig_tree, hf_dbc_signal_val[sig_number], tvb, 0, 8, val);
		if (s_unit[0])
			proto_tree_add_string(sig_tree, hf_dbc_signal_unit[sig_number], tvb, 0, 8, s_unit);
		else if (s_vals[0])
			proto_tree_add_string(sig_tree, hf_dbc_signal_unit[sig_number], tvb, 0, 8, s_vals);

		proto_tree_add_double(sig_tree, hf_dbc_signal_val_min[sig_number], tvb, 0, 8, signall->min_value);
		proto_tree_add_double(sig_tree, hf_dbc_signal_val_max[sig_number], tvb, 0, 8, signall->max_value);
	}

	if (dbc_multi_row && dbc_multi_row_active)
	{
		if (s_vals[0] && !s_unit[0])
		{
			proto_item_append_text(tree, " %s: %s (%g)", signall->name, s_vals, val);
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s: %s (%g)", signall->name, s_vals, val);
		}
		else
		{
			proto_item_append_text(tree, " %s: %g%s", signall->name, val, s_unit);
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s: %g%s", signall->name, val, s_unit);
		}
	}
	else
	{
		const char *sepa = (sig_number > 0) ? "," : "";

		if (s_vals[0] && !s_unit[0])
		{
			proto_item_append_text(tree, "%s S%d: %s", sepa, sig_number, s_vals);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s S%d: %s", sepa, sig_number, s_vals);
		}
		else
		{
			proto_item_append_text(tree, "%s S%d: %g%s", sepa, sig_number, val, s_unit);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s S%d: %g%s", sepa, sig_number, val, s_unit);
		}
	}
}

static int
dissect_dbc_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct dbc_message *message)
{
	struct dbc_signal *signall;
	guint skip_number = 0;
	guint frame_no = 0;
	int sig_number = 0;

	proto_tree *msg_tree;
	proto_item *ti;

	if (dbc_multi_row && dbc_multi_row_active)
	{
		guint64 file_off = (guint64) pinfo->fd->file_off;

		skip_number = (file_off & MAX_SIGNAL);
		frame_no    = (file_off >> 10) & 0xFFFF;

		col_append_fstr(pinfo->cinfo, COL_INFO, "[%u] ", frame_no);
		proto_tree_add_uint(tree, hf_dbc_frame_num, tvb, 0, 8, frame_no);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s", message->name);

	ti = proto_tree_add_item(tree, message->hf_id, tvb, 0, -1, ENC_NA);
	msg_tree = proto_item_add_subtree(ti, message->ett_id);

	if (message->file->ftype == DBC_FILE_TYPE_J1939)
		proto_tree_add_uint(msg_tree, hf_dbc_message_id, tvb, 0, 8, message->id >> 8);
	else
		proto_tree_add_uint(msg_tree, hf_dbc_message_id, tvb, 0, 8, message->id);
	proto_tree_add_uint(msg_tree, hf_dbc_message_orig_id, tvb, 0, 8, message->orig_id);
	proto_tree_add_string(msg_tree, hf_dbc_message_name, tvb, 0, 8, message->name);
	if (message->comment)
		proto_tree_add_string(msg_tree, hf_dbc_message_comment, tvb, 0, 8, message->comment);

	for (signall = message->signals; signall; signall = signall->next)
	{
		if (skip_number != 0)
		{
			skip_number--;
			continue;
		}

		dissect_dbc_message_signal(tvb, pinfo, msg_tree, signall, sig_number);
		sig_number++;

		if (dbc_multi_row && dbc_multi_row_active)
			break;
	}

	return tvb_captured_length(tvb);
}

static int
dissect_dbc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct can_identifier *can_id = (struct can_identifier *) data;
	struct dbc_message *message;

	proto_tree *dbc_tree;
	proto_item *ti;

	if (!can_id)
		return 0;

#ifdef BUILDING_WITH_CAN_LIVE
	if (can_id && PINFO_FD_VISITED(pinfo) == 0)
		can_live_insert(can_id->id, tvb, pinfo);
#endif

	message = dbc_message_lookup(can_id->id);
	if (!message)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN DBC");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_dbc, tvb, 0, -1, ENC_NA);
	dbc_tree = proto_item_add_subtree(ti, ett_dbc);

	proto_tree_add_string(dbc_tree, hf_dbc_module_name, tvb, 0, 0, message->file->path);

	return dissect_dbc_message(tvb, pinfo, dbc_tree, message);
}

/* Register */

static void
dbc_deregister_message(gpointer key _U_, gpointer value, gpointer data _U_)
{
	struct dbc_message *message = (struct dbc_message *) value;
	struct dbc_signal *signall;

	for (signall = message->signals; signall; signall = signall->next)
	{
		proto_deregister_field(proto_dbc, signall->hf_id);
		signall->hf_id = -1;
	}

	proto_deregister_field(proto_dbc, message->hf_id);
	message->hf_id = -1;

//	proto_add_deregistered_data (hf);
}

static void
dbc_register_message(gpointer key _U_, gpointer value, gpointer data _U_)
{
	struct dbc_message *message = (struct dbc_message *) value;
	struct dbc_signal *signall;
	char filter_prefix[512];

	static const hf_register_info sample_hfi =
	{
		/* p_id */ NULL,
		/* hfinfo */ {
			/* name */"name",
			/* abbrev */"abbrev",
			/* type */FT_NONE,
			/* display */BASE_NONE,
			/* strings */NULL,
			/* bitmask */0x0,
			/* blurb */"blurb",
			HFILL
		}
	};

	int *etts[1];

	hf_register_info *hfi;

	filter_prefix[0] = '\0';

	if (message->file && message->file->path)
	{
		const char *tmp = message->file->path;
		char *s;

		s = strrchr(tmp, '/');
		if (s)
			tmp = s + 1;
		s = strrchr(tmp, '\\');
		if (s)
			tmp = s + 1;

		g_strlcpy(filter_prefix, tmp, sizeof(filter_prefix));
		s = strchr(tmp, '.');
		if (s)
			*s = '\0';
	}

	/* register message */
	hfi = (hf_register_info *) g_memdup(&sample_hfi, sizeof(sample_hfi));
	hfi->p_id = &(message->hf_id);
	hfi->hfinfo.name = message->name;
	hfi->hfinfo.abbrev = g_strdup_printf("can-dbc.%s.%s", filter_prefix, message->name);
	hfi->hfinfo.blurb = message->comment;

	proto_register_field_array(proto_dbc, hfi, 1);

	etts[0] = &(message->ett_id);
	proto_register_subtree_array(etts, 1);

	/* register signals */
	for (signall = message->signals; signall; signall = signall->next)
	{
		hfi = (hf_register_info *) g_memdup(&sample_hfi, sizeof(sample_hfi));
		hfi->p_id = &(signall->hf_id);
		hfi->hfinfo.name = signall->name;
		hfi->hfinfo.abbrev = g_strdup_printf("can-dbc.%s.%s.%s", filter_prefix, message->name, signall->name); 
		hfi->hfinfo.blurb = signall->comment;

		if (signall->flags & DBC_SIGNAL_JUST_BIT)
		{
			unsigned int b = signall->bit_length;

			if (signall->flags & DBC_SIGNAL_UNSIGNED)
			{
				hfi->hfinfo.type = 
					(b < 9) ? FT_UINT8 : (b < 17) ? FT_UINT16 : (b < 25) ? FT_UINT24 : (b < 33) ? FT_UINT32 : (b < 41) ? FT_UINT40 : (b < 49) ? FT_UINT48 : (b < 57) ? FT_UINT56 : FT_UINT64;

				if (signall->unit)
					hfi->hfinfo.display = BASE_DEC;
				else
					hfi->hfinfo.display = BASE_DEC_HEX;
			}
			else
			{
				hfi->hfinfo.type =
					(b < 9) ? FT_INT8 : (b < 17) ? FT_INT16 : (b < 25) ? FT_INT24 : (b < 33) ? FT_INT32 : (b < 41) ? FT_INT40 : (b < 49) ? FT_INT48 : (b < 57) ? FT_INT56 : FT_INT64;
				hfi->hfinfo.display = BASE_DEC;
			}

			hfi->hfinfo.strings = signall->vals;
		}
		else
		{
			hfi->hfinfo.type = FT_DOUBLE;
		}

		proto_register_field_array(proto_dbc, hfi, 1);

		etts[0] = &(signall->ett_id);
		proto_register_subtree_array(etts, 1);
	}
}

static gboolean
dbc_files_uat_fld_fileopen_chk_cb(void *r _U_, const char *p, guint len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
    ws_statb64 st;
	size_t i;

    if (!p || !strlen(p))
	{
        *err = g_strdup("No filename given.");
        return FALSE;
    }

	if (ws_stat64(p, &st) != 0)
	{
		*err = g_strdup_printf("File '%s' does not exist or access is denied.", p);
        return FALSE;
    }

	{
		const char *s = strrchr(p, '/');
		if (s)
			p = s + 1;
		s = strrchr(p, '\\');
		if (s)
			p = s + 1;
	}

	for (i = 0; p[i]; i++)
	{
		char ch = p[i];

		if (ch >= '0' && ch <= '9') continue;
		if (ch >= 'A' && ch <= 'Z') continue;
		if (ch >= 'a' && ch <= 'z') continue;
		if (ch == '-' || ch == '.' || ch == '_') continue;

		*err = g_strdup_printf("Please rename '%s' (wrong char: '%c'). DBC filename is used to create Wireshark filter name. It can only have letters, digits or '-_.'", p, ch);
		return FALSE;
	}

    *err = NULL;
    return TRUE;
}


UAT_CSTRING_CB_DEF(dbc_files, filename, struct dbc_files_uat_data)
UAT_VS_DEF(dbc_files, ftype, struct dbc_files_uat_data, int, 0, "General")

static void
dbc_files_uat_initialize_cb(void)
{
	guint i;

	if (dbc_msg_ids)
	{
		g_hash_table_foreach(dbc_msg_ids, dbc_deregister_message, NULL);
		g_hash_table_destroy(dbc_msg_ids);
	}

	dbc_msg_ids = g_hash_table_new(g_direct_hash, g_direct_equal);

	for (i = 0; i < num_dbc_files_uat_data; i++)
	{
		guint32 mask;

		switch (dbc_files_uat_data[i].ftype)
		{
			case DBC_FILE_TYPE_J1939:
				mask = 0x03FFFF00;
				break;

			case DBC_FILE_TYPE_GENERAL:
			default:
				mask = 0xFFFFFFFF;
				break;
		}

		dbc_parse_debug(DBC_PARSER_INFO, "::: reading %s (mask %.8x)\n", dbc_files_uat_data[i].filename, mask);
		dbc_read_file(dbc_files_uat_data[i].filename, dbc_files_uat_data[i].ftype, mask);
	}

	g_hash_table_foreach(dbc_msg_ids, dbc_register_message, NULL);
}

static gboolean dbc_files_uat_data_update_cb(void *p, char **err)
{
  //  *err = g_strdup_printf("Length of Encryption key limited to %d octets (%d hex characters).", MAX_KEY_SIZE, MAX_KEY_SIZE * 2);
  //  return FALSE;

	*err = NULL;
	return TRUE;
}

static wtap dbc_multirow_orig_wtap;
static gint64 dbc_multirow_data_off = 0;
static int dbc_multirow_signal_count = 0;
static guint dbc_multirow_frame_no = 0;

static gboolean
dbc_multirow_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	gboolean ret;

	if (!dbc_multirow_signal_count)
	{
		gint64 real_offset;

		ret = dbc_multirow_orig_wtap.subtype_read(wth, err, err_info, &real_offset);
		if (ret)
		{
			struct dbc_message *message;

			guint8 *ptr = wtap_buf_ptr(wth);

			guint32 can_id = pntoh32(ptr);

#define CAN_EFF_FLAG 0x80000000 /* EFF/SFF is set in the MSB */
#define CAN_EFF_MASK 0x1FFFFFFF /* extended frame format (EFF) */
#define CAN_SFF_MASK 0x000007FF /* standard frame format (SFF) */

			if (can_id & CAN_EFF_FLAG)
				can_id &= CAN_EFF_MASK;
			else
				can_id &= CAN_SFF_MASK;

			message = dbc_message_lookup(can_id);
			if (message)
			{
				dbc_multirow_signal_count = message->signal_count - 1;
				dbc_multirow_signal_count = MIN(dbc_multirow_signal_count, MAX_SIGNAL);
			}

			dbc_multirow_frame_no = (dbc_multirow_frame_no + 1) & 0xFFFF;

			*data_offset = (real_offset << 30) | (dbc_multirow_frame_no << 10) | 0;
			dbc_multirow_data_off = *data_offset;
		}
	}
	else
	{
		dbc_multirow_signal_count--;

		*data_offset = ++dbc_multirow_data_off;
		ret = TRUE;
	}

	return ret;
}

static gboolean
dbc_multirow_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	seek_off >>= 30;

	return dbc_multirow_orig_wtap.subtype_seek_read(wth, seek_off, phdr, buf, err, err_info);
}

static wtap_open_return_val
dbc_multirow_open(wtap *wth, int *err, gchar **err_info, const char *name)
{
	wtap_open_return_val ret = WTAP_OPEN_NOT_MINE;
	unsigned int real_type;

	dbc_multi_row_active = FALSE;
	if (dbc_multi_row == FALSE)
		return ret;

	real_type = open_info_name_to_type(name);
	if (real_type != WTAP_TYPE_AUTO)
		ret = open_routines[real_type - 1].open_routine(wth, err, err_info); 

	if (ret == WTAP_OPEN_MINE && wth->file_encap == WTAP_ENCAP_SOCKETCAN)
	{
		dbc_multirow_orig_wtap = *wth;

		wth->subtype_read      = dbc_multirow_read;
		wth->subtype_seek_read = dbc_multirow_seek_read;

		dbc_multirow_frame_no = 0;
		dbc_multirow_signal_count = 0;
		dbc_multi_row_active = TRUE;
	}

	return ret;
}

static wtap_open_return_val
dbc_multirow_open_pcap(wtap *wth, int *err, gchar **err_info)
{
	return dbc_multirow_open(wth, err, err_info, "Wireshark/tcpdump/... - pcap");
}

static wtap_open_return_val
dbc_multirow_open_pcapng(wtap *wth, int *err, gchar **err_info)
{
	return dbc_multirow_open(wth, err, err_info, "Wireshark/... - pcapng");
}

static wtap_open_return_val
dbc_multirow_open_cllog(wtap *wth, int *err, gchar **err_info)
{
	return dbc_multirow_open(wth, err, err_info, "CanLogger");
}

void
proto_register_dbc(void)
{
	static uat_field_t dbc_files_uat_flds[] =
	{
		UAT_FLD_FILENAME_OTHER(dbc_files, filename, "DBC filename", dbc_files_uat_fld_fileopen_chk_cb, "DBC filename"),
		UAT_FLD_VS(dbc_files, ftype, "DBC Type", dbc_files_type_vals, "DBC Type"),
		UAT_END_FIELDS
	};

	static struct open_info dbc_multirow_pcap =
	{ 
		"DBC Multirow PCAP", OPEN_INFO_MAGIC, dbc_multirow_open_pcap, "pcap", NULL, NULL
	};

	static struct open_info dbc_multirow_pcapng =
	{ 
		"DBC Multirow PCAPNG", OPEN_INFO_MAGIC, dbc_multirow_open_pcapng, "pcapng", NULL, NULL
	};

	static struct open_info dbc_multirow_cllog =
	{ 
		"DBC Multirow CLLLog", OPEN_INFO_MAGIC, dbc_multirow_open_cllog, "cll", NULL, NULL
	};


	static hf_register_info signal_hf_example[] =
	{
		{ &hf_dbc_signal_val[0],
			{ "DBC Signal", "dbc.signal_val_", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_dbc_signal_unit[0],
			{ "DBC Signal Unit", "dbc.signal_unit_", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
	};

	static hf_register_info hf[] =
	{
		{ &hf_dbc_module_name,
			{ "DBC File Name", "can-dbc.file_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_dbc_frame_num,
			{ "Frame number", "can-dbc.frame_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_dbc_message_id,
			{ "Message ID (masked)", "can-dbc.message_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_dbc_message_orig_id,
			{ "Message ID (original from DBC)", "can-dbc.message_orig_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_dbc_message_name,
			{ "Message Name", "can-dbc.message_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_dbc_message_comment,
			{ "Message Comment", "can-dbc.message_comment", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
	};

	static ei_register_info ei[] = {
		{ &ei_dbc_signal_max, { "can-dbc.signal_max", PI_SEQUENCE, PI_WARN, "WARNING: value is above MAX", EXPFILL }},
		{ &ei_dbc_signal_min, { "can-dbc.signal_min", PI_SEQUENCE, PI_WARN, "WARNING: value is below MIN", EXPFILL }},
	};

	static int *ett[] =
	{
		&ett_dbc
	};

	module_t *dbc_module;
	uat_t *dbc_files;
	int i;

	proto_dbc = proto_register_protocol("CAN DBC", "CAN DBC", "can-dbc");
	proto_register_field_array(proto_dbc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_register_field_array(expert_register_protocol(proto_dbc), ei, array_length(ei));

	for (i = 0; i < MAX_SIGNAL; i++)
	{
		hf_register_info *signal_hf;

		hf_dbc_signal_name[i] = -1;
		hf_dbc_signal_comment[i] = -1;
		hf_dbc_signal_val[i] = -1;
		hf_dbc_signal_unit[i] = -1;
		hf_dbc_signal_val_min[i] = -1;
		hf_dbc_signal_val_max[i] = -1;

		signal_hf = (hf_register_info *) g_memdup(&signal_hf_example[0], sizeof(*signal_hf));
		signal_hf->p_id = &hf_dbc_signal_val[i];
		signal_hf->hfinfo.name   = g_strdup_printf("DBC Signal Converted Value #%d", i);
		signal_hf->hfinfo.abbrev = g_strdup_printf("can-dbc.signal_val_%d", i);
		proto_register_field_array(proto_dbc, signal_hf, 1);

		signal_hf = (hf_register_info *) g_memdup(&signal_hf_example[0], sizeof(*signal_hf));
		signal_hf->p_id = &hf_dbc_signal_val_min[i];
		signal_hf->hfinfo.name   = g_strdup_printf("DBC Signal Converted Value Min #%d", i);
		signal_hf->hfinfo.abbrev = g_strdup_printf("can-dbc.signal_val_min_%d", i);
		proto_register_field_array(proto_dbc, signal_hf, 1);

		signal_hf = (hf_register_info *) g_memdup(&signal_hf_example[0], sizeof(*signal_hf));
		signal_hf->p_id = &hf_dbc_signal_val_max[i];
		signal_hf->hfinfo.name   = g_strdup_printf("DBC Signal Converted Value Max #%d", i);
		signal_hf->hfinfo.abbrev = g_strdup_printf("can-dbc.signal_val_max_%d", i);
		proto_register_field_array(proto_dbc, signal_hf, 1);

		signal_hf = (hf_register_info *) g_memdup(&signal_hf_example[1], sizeof(*signal_hf));
		signal_hf->p_id = &hf_dbc_signal_unit[i];
		signal_hf->hfinfo.name   = g_strdup_printf("DBC Signal Unit #%d", i);
		signal_hf->hfinfo.abbrev = g_strdup_printf("can-dbc.signal_unit_%d", i);
		proto_register_field_array(proto_dbc, signal_hf, 1);

		signal_hf = (hf_register_info *) g_memdup(&signal_hf_example[1], sizeof(*signal_hf));
		signal_hf->p_id = &hf_dbc_signal_name[i];
		signal_hf->hfinfo.name   = g_strdup_printf("DBC Signal Name #%d", i);
		signal_hf->hfinfo.abbrev = g_strdup_printf("can-dbc.signal_name_%d", i);
		proto_register_field_array(proto_dbc, signal_hf, 1);

		signal_hf = (hf_register_info *) g_memdup(&signal_hf_example[1], sizeof(*signal_hf));
		signal_hf->p_id = &hf_dbc_signal_comment[i];
		signal_hf->hfinfo.name   = g_strdup_printf("DBC Signal Comment #%d", i);
		signal_hf->hfinfo.abbrev = g_strdup_printf("can-dbc.signal_comment_%d", i);
		proto_register_field_array(proto_dbc, signal_hf, 1);
	}

	dbc_module = prefs_register_protocol(proto_dbc, NULL);

	dbc_files = uat_new("CAN DBC File List",
		sizeof(struct dbc_files_uat_data),
		"dbc_files",
		TRUE,
		&dbc_files_uat_data,
		&num_dbc_files_uat_data,    /* numitems_ptr */
		UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
		NULL,                   /* Help section (currently a wiki page) */
		NULL,
		dbc_files_uat_data_update_cb,
		NULL,
		dbc_files_uat_initialize_cb,
		NULL,
		dbc_files_uat_flds);

	prefs_register_uat_preference(dbc_module, "file_list", "DBC File Table", "DBC File List", dbc_files);
	prefs_register_bool_preference(dbc_module, "multi_row", "Signal per row", "Duplicate signals frame to make single signal in row", &dbc_multi_row);
	prefs_register_static_text_preference(dbc_module, "advert_note", "This plugin has been developed for CSS Electronics and is available for free. For more info on the plugin and our CAN bus data loggers, please check out www.csselectronics.com", "This plugin has been developed for CSS Electronics and is available for free. For more info on the plugin and our CAN bus data loggers, please check out www.csselectronics.com");

	wtap_register_open_info(&dbc_multirow_cllog, TRUE);
	wtap_register_open_info(&dbc_multirow_pcap, TRUE);
	wtap_register_open_info(&dbc_multirow_pcapng, TRUE);
}

void
proto_reg_handoff_dbc(void)
{
	dissector_handle_t dbc_handle;

	dbc_handle = create_dissector_handle(dissect_dbc, proto_dbc);
	dissector_add_for_decode_as("can.subdissector", dbc_handle);
}
