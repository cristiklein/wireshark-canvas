#include "config.h"

#include <wiretap/wtap-int.h>
#include <wiretap/file_wrappers.h>

#include "cCLLog.c"

#define CAN_EFF_MASK 0x1FFFFFFF /* extended frame format (EFF) */
#define CAN_SFF_MASK 0x000007FF /* standard frame format (SFF) */

static gboolean
wtap_cllog_read_common(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf, int *err _U_, gchar **err_info _U_)
{
	cCLLog_obj_t *clLog = (cCLLog_obj_t *) wth->priv;
	cCLLog_message_t logEntry;
	uint8_t res;

	clLog->file_data = fh;

	res = cCLLog_fgets(clLog, &logEntry);
	if (res > 0)
	{
		guint8 *can_data;

		phdr->rec_type = REC_TYPE_PACKET;
		phdr->presence_flags = WTAP_HAS_TS;

		phdr->ts.secs = logEntry.timestamp.abs.epoch;
		phdr->ts.nsecs = logEntry.timestamp.abs.ms * 1000U * 1000U;

		phdr->caplen = 8 + logEntry.length;
		phdr->len = 8 + logEntry.length;

		if (logEntry.msgType == msg_tx_standard_e || logEntry.msgType == msg_tx_extended_e)
		{
			phdr->presence_flags |= WTAP_HAS_PACK_FLAGS;
			phdr->pack_flags = 0x00000002;
		}
		else if (logEntry.msgType == msg_rx_standard_e || logEntry.msgType == msg_rx_extended_e)
		{
			phdr->presence_flags |= WTAP_HAS_PACK_FLAGS;
			phdr->pack_flags = 0x00000001;
		}

		ws_buffer_assure_space(buf, phdr->caplen);
		can_data = ws_buffer_start_ptr(buf);

		can_data[0] = (logEntry.id >> 24);
		can_data[1] = (logEntry.id >> 16);
		can_data[2] = (logEntry.id >>  8);
		can_data[3] = (logEntry.id >>  0);
		can_data[4] = logEntry.length;
		can_data[5] = 0;
		can_data[6] = 0;
		can_data[7] = 0;

		if (logEntry.msgType == msg_tx_extended_e || logEntry.msgType == msg_rx_extended_e || (logEntry.id & CAN_EFF_MASK) > CAN_SFF_MASK)
			can_data[0] |= 0x80;

		memcpy(&can_data[8], logEntry.data, logEntry.length);
		return TRUE;
	}

	return FALSE;
}

static gboolean
wtap_cllog_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return wtap_cllog_read_common(wth, wth->fh, &wth->phdr, wth->frame_buffer, err, err_info);
}

static gboolean
wtap_cllog_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	return wtap_cllog_read_common(wth, wth->random_fh, phdr, buf, err, err_info);
}

static void
wtap_cllog_close(wtap *wth)
{
	cCLLog_obj_t *clLog = (cCLLog_obj_t *) wth->priv;

	cCLLog_dtor(clLog);
}

static int
cllog_rewind_impl(void *stream)
{
	int err;

	return (int) file_seek((FILE_T) stream, 0, SEEK_SET, &err);
}

static char *
cllog_gets_impl(char *s, int size, void *stream)
{
	return file_gets(s, size, (FILE_T)stream);
}

static wtap_open_return_val
wtap_cllog_open(wtap *wth, int *err _U_, gchar **err_info _U_)
{
	cCLLog_obj_t *clLog;
	bool ret;

	clLog = g_new0(cCLLog_obj_t, 1);
	ret = cCLLog_ctor_wireshark(clLog, cllog_gets_impl, cllog_rewind_impl, wth->fh);
	if (!ret)
	{
		g_free(clLog);
		return WTAP_OPEN_NOT_MINE;
	}

	wth->priv = clLog;

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_HCIDUMP;
	wth->file_encap = WTAP_ENCAP_SOCKETCAN;
	wth->snapshot_length = 0;

	wth->subtype_read = wtap_cllog_read;
	wth->subtype_seek_read = wtap_cllog_seek_read;
	wth->subtype_close = wtap_cllog_close;
	wth->file_tsprec = WTAP_TSPREC_MSEC;

	return WTAP_OPEN_MINE;
}

static void
wtap_register_canlogger(void)
{
	static struct open_info cllog_open_info =
	{ 
		"CanLogger", OPEN_INFO_MAGIC, wtap_cllog_open, "cll", NULL, NULL
	};

	wtap_register_open_info(&cllog_open_info, FALSE);
}

void
proto_register_cll(void)
{
	wtap_register_canlogger();
}
