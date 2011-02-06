/*
 * MessagePack-RPC Dissector for Wireshark.
 *
 * Copyright (C) 2009 Hiroki Kumazaki
 * and is licensed under BSD.
 *
 */

#include <glib.h>

extern "C" {
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
}

#include <string.h>

#include <msgpack.hpp>
#include <sstream>

#define PROTO_TAG_MSGPACK "MSGPACK"
#define MSGPACK_FULLNAME "MessagePack-RPC"
#define MSGPACK_SHORTNAME "MsgpackRPC"	
#define MSGPACK_ABBREV "msgpack-rpc"

#define MSPPACK_RPC_PORT 19860

/* Initialize the protocol and registered fields */
static int proto_msgpack = -1;
	
//static dissector_handle_t data_handle=NULL;
static dissector_handle_t msgpack_rpc_handle=NULL;

extern "C"
gboolean heur_dissect_msgpack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern "C"
void dissect_msgpack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void)heur_dissect_msgpack(tvb, pinfo, tree);
}

extern "C"
void proto_reg_handoff_msgpack(void)
{
	static gboolean initialized=FALSE;
	
	if (!initialized) {
		msgpack_rpc_handle = find_dissector(MSGPACK_ABBREV);
		if(msgpack_rpc_handle == NULL){
			msgpack_rpc_handle = create_dissector_handle(dissect_msgpack, proto_msgpack);
		}
		dissector_add("tcp.port", MSPPACK_RPC_PORT , msgpack_rpc_handle);
		initialized = TRUE;
	}
}

enum message_type{
	type_request = 0,
	type_response = 1,
	type_notification = 2,
};

static gint ett_msgpack_rpc = -1;
static gint hf_msgpack_request = -1;
static gint hf_msgpack_response = -1;
static gint hf_msgpack_notificaton = -1;
static gint hf_msgpack_msgid = -1;
static gint hf_msgpack_method = -1;
static gint hf_msgpack_error = -1;
static gint hf_msgpack_param = -1;
static gint hf_msgpack_result = -1;
static gint* type_map[] = {
	&hf_msgpack_request,
	&hf_msgpack_response,
	&hf_msgpack_notificaton
};
//static gint hf_msgpack_param = -1;


extern "C"
void proto_register_msgpack(void)
{
	/* Initialization */
	
	/* A header field is something you can search/filter on.
	 * 
	 * We create a structure to register our fields. It consists of an
	 * array of hf_register_info structures, each of which are of the format
	 * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	 */
	static hf_register_info hf[] = {
		{ &hf_msgpack_request,
			{"Request Message", "msgpack.request", FT_NONE, BASE_NONE, NULL, 0x0,
			 "request", HFILL}},
		{ &hf_msgpack_response,
			{"Response Message", "msgpack.response", FT_NONE, BASE_NONE, NULL, 0x0,
			 "response", HFILL}},
		{ &hf_msgpack_notificaton,
			{"Notification Message", "msgpack.notification", FT_NONE, BASE_NONE, NULL, 0x0,
			 "notification", HFILL}},
		{ &hf_msgpack_msgid,
			{"Message ID", "msgpack.msgid", FT_UINT32, BASE_DEC, NULL, 0x0,
			 "msgid", HFILL}},
		{ &hf_msgpack_method,
			{"RPC Method", "msgpack.method", FT_STRING, BASE_NONE, NULL, 0x0,
			 "method", HFILL}},
		{ &hf_msgpack_param,
			{"RPC Parameters", "msgpack.parameter", FT_STRING, BASE_NONE, NULL, 0x0,
			 "parameter", HFILL}},
		{ &hf_msgpack_error,
			{"RPC Error", "msgpack.error", FT_STRING, BASE_NONE, NULL, 0x0,
			 "error", HFILL}},
		{ &hf_msgpack_result,
			{"RPC Result", "msgpack.result", FT_STRING, BASE_NONE, NULL, 0x0,
			 "result", HFILL}}
	};
	

	static gint *ett[] = {
		&ett_msgpack_rpc,
	};

	proto_msgpack = proto_register_protocol(MSGPACK_FULLNAME, "MsgpackRPC", MSGPACK_ABBREV);
	proto_register_field_array (proto_msgpack, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	heur_dissector_add("tcp", heur_dissect_msgpack, proto_msgpack);
}

#include <string>

bool is_unsigned_integer(const guint8* const buff)
{
	if((buff[0] & 0xcc) == 0xcc && (buff[0] & 0x30) == 0){return true;}
	if((buff[0] & 0x80) == 0){return true;}
	return false;
}

struct data_type{
	enum name{
		none,
		integer,
		strings
	};
};

struct pattern{
	int* hf;
	data_type::name type;
	int parse_and_add(msgpack::unpacker& unp, proto_tree* ti,	tvbuff_t* tvb,
										int offset)const{
		msgpack::unpacked result;
		const size_t before = unp.nonparsed_size();
		if(!unp.next(&result)){

			return 1;
		};
		const int length = before - unp.nonparsed_size();
		std::stringstream ss;
		try{
			msgpack::object obj(result.get());
			ss << obj;
		}catch(...){
		}
		if(type == data_type::strings){
			proto_tree_add_string(ti, *hf, tvb,	offset, length, ss.str().c_str());
		}else if(type == data_type::integer){
			proto_tree_add_uint(ti, *hf, tvb,	offset, length, atoi(ss.str().c_str()));
		}else if(type == data_type::none){
			proto_tree_add_item(ti, *hf, tvb, 1, 1, FALSE);
		}
		return length;
	}
};

static const pattern msg_matrix[3][4] = {
	{// request
		{&hf_msgpack_request, data_type::none},
		{&hf_msgpack_msgid, data_type::integer},
		{&hf_msgpack_method, data_type::strings},
		{&hf_msgpack_param, data_type::strings}
	},
	{// response
		{&hf_msgpack_response, data_type::none},
		{&hf_msgpack_msgid, data_type::integer},
		{&hf_msgpack_error, data_type::strings},
		{&hf_msgpack_result, data_type::strings}
	},
	{// notification
		{&hf_msgpack_notificaton, data_type::none},
		{&hf_msgpack_method, data_type::strings},
		{&hf_msgpack_param, data_type::strings}
	}
};
static const int matrix_size[] = {4,4,3};
static const char* rpc_info[] = {
	"Request",
	"Response",
	"Notification"
};

int get_type(const guint8* const buff){
	if(buff[0] == 0x94 && buff[1] == 0x00 && is_unsigned_integer(&buff[2])){
		return type_request;
	}else if(buff[0] == 0x94 && buff[1] == 0x01 && is_unsigned_integer(&buff[2])){
		return type_response;
	}else if(buff[0] == 0x93 && buff[1] == 0x02){
		return type_notification;
	}else{
		DISSECTOR_ASSERT(!"msgpack-rpc: it is not a msgpack-rpc packet.\n");
		return -1;
	}
}

extern "C"

gboolean heur_dissect_msgpack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if(tvb_length(tvb) < 4){return 0;}
	int offset = 0;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, MSGPACK_FULLNAME);

  proto_item* ti = proto_tree_add_item(tree, proto_msgpack, tvb, offset, -1, FALSE);
  proto_tree* msgpack_tree = proto_item_add_subtree(ti, ett_msgpack_rpc);
	
	if(tree != NULL){
		/* get type */
		const guint8* const buff = tvb->real_data;
		const char type = get_type(buff);
		if(type < 0){return 0;}
		col_set_str(pinfo->cinfo, COL_INFO, rpc_info[type]);
		{
			const int length = tvb->reported_length;
			msgpack::unpacker unp(length);
			int offset = 1;
			memcpy(unp.buffer(), &buff[offset], length - offset);
			unp.buffer_consumed(length);

			for(int i=0; i<matrix_size[type]; ++i){
				offset += msg_matrix[type][i].parse_and_add(unp, ti, tvb, offset);
			}
		}
		assert(0 <= type && type <= 2);
	}
		
	return 1;
}
