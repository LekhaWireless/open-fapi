/**
 *
 * Copyright (c) Makarand Kulkarni, 2017-18 (makarand@lekhawireless.com)
 *
 * see license file for licensing terms
 */
#include "config.h"

#include <epan/packet.h>

#define FAPI_PORT_RD 58140
#define FAPI_PORT_WR 58142

static int proto_fapi                                   = -1;

static int hf_fapi_message_type                         = -1;
static int hf_fapi_message_len                          = -1;
static int hf_fapi_message_vendor_tlv_len               = -1;
static int hf_fapi_message_body                         = -1;

static int hf_fapi_subframe_ind                         = -1;
static int hf_fapi_subframe_ind_sfnsf                   = -1;
static int hf_fapi_subframe_ind_sfnsf_sfn               = -1;
static int hf_fapi_subframe_ind_sfnsf_sf                = -1;
static int hf_fapi_subframe_ind_padding                 = -1;

static int hf_fapi_dlconfig_req                         = -1;
static int hf_fapi_dlconfig_req_len                     = -1;
static int hf_fapi_dlconfig_req_cfi                     = -1;
static int hf_fapi_dlconfig_req_numDCI                  = -1;
static int hf_fapi_dlconfig_req_numOfPDU                = -1;
static int hf_fapi_dlconfig_req_txPowerForPCFICH        = -1;
static int hf_fapi_dlconfig_req_numOfPDSCHRNTI          = -1;
static int hf_fapi_dlconfig_req_padding                 = -1;
static int hf_fapi_dlconfig_req_pdu_info                = -1;
static int hf_fapi_dlconfig_req_pdu_info_pdutype	= -1;
static int hf_fapi_dlconfig_req_pdu_info_pdusize	= -1;
static int hf_fapi_dlconfig_req_pdu_info_pdupadding	= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion	= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dciformat						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_cceIndex						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_rnti							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlvl					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment				= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs 						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rv						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_dai						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_padding					= -1;


static gint ett_fapi_message_type                       = -1;
static gint ett_fapi_message_len                        = -1;
static gint ett_fapi_message_vendor_tlv_len             = -1;
static gint ett_fapi_message_body                        = -1;

static gint ett_fapi_subframe_ind                       = -1;
static gint ett_fapi_subframe_ind_sfnsf                 = -1;
static gint ett_fapi_subframe_ind_sfnsf_sfn             = -1;
static gint ett_fapi_subframe_ind_sfnsf_sf              = -1;
static gint ett_fapi_subframe_ind_padding               = -1;

static gint ett_fapi_dlconfig_req                       = -1;
static gint ett_fapi_dlconfig_req_len                   = -1;
static gint ett_fapi_dlconfig_req_cfi                   = -1;
static gint ett_fapi_dlconfig_req_numDCI                = -1;
static gint ett_fapi_dlconfig_req_numOfPDU              = -1;
static gint ett_fapi_dlconfig_req_txPowerForPCFICH      = -1;
static gint ett_fapi_dlconfig_req_numOfPDSCHRNTI        = -1;
static gint ett_fapi_dlconfig_req_padding               = -1;
static gint ett_fapi_dlconfig_req_pdu_info              = -1;
static gint ett_fapi_dlconfig_req_pdu_info_pdutype	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pdusize	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pdupadding	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu				= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dciformat			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_cceIndex			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_rnti				= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlvl 		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment 	= -1;

static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs 		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rv			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_dai		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_padding		= -1;

static const value_string message_id_vals[] = {
    { 0x00, "PARAM.request" },
    { 0x01, "PARAM.response" },
    { 0x02, "CELL_CONFIG.request" },
    { 0x03, "CELL_CONFIG.response" },
    { 0x04, "START.request" },
    { 0x05, "STOP.request" },
    { 0x06, "STOP.indication" },
    { 0x07, "UE_CONFIG.request" },
    { 0x08, "UE_CONFIG.response" },
    { 0x09, "ERROR.indication" },
  
    { 0x80, "DL_CONFIG.request" },
    { 0x81, "UL_CONFIG.request" },
    { 0x82, "UL_SUBFRAME.indication" },
    { 0x83, "DL_HI_DCI0.request" },
    { 0x84, "DL_TX.request" },
    { 0x85, "UL_HARQ.indication" },
    { 0x86, "UL_CRC.indication" },
    { 0x87, "UL_RX_ULSCH.indication" },
    { 0x88, "UL_RACH.indication" },
    { 0x89, "UL_RX_SR.indication" },
    { 0x8a, "UL_RX_CQI.indication" }
}; 

static const value_string dlconfig_req_pdutype_vals[] = {
	{ 0, "DCI PDU" },
	{ 1, "BCH PDU" },
	{ 2, "MCH PDU" },
	{ 3, "DLSCH PDU" },
	{ 4, "PCH PDU" },
};

static const value_string dlconfig_req_dciformat_vals[] = {
	{0, "1" },
	{1, "1A"},
	{2, "1B"},
	{3, "1C"},
	{4, "1D"},
	{5, "2" },
	{6, "2A"},
};

static const value_string dlconfig_req_dci1a_vrbassignment_vals[] = {
	{0, "localized"},
	{1, "distributed"},
};

static const value_string dlconfig_req_dci1a_rntitype_vals[] = {
	{1, "C-RNTI"},
	{2, "RA-RNTI, P-RNTI or SI-RNTI"},
	{3, "SPS-RNTI"},
};

static int dissect_fapi_subframe_sfnsf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_)
{
        proto_item *fapi_subframe_ind_sfnsf_item = proto_tree_add_item(tree, hf_fapi_subframe_ind_sfnsf, tvb, offset, 2, ENC_NA);

        proto_tree *fapi_subframe_ind_sfnsf_sfn_tree = proto_item_add_subtree(fapi_subframe_ind_sfnsf_item, ett_fapi_subframe_ind_sfnsf_sfn);
        proto_tree_add_item(fapi_subframe_ind_sfnsf_sfn_tree, hf_fapi_subframe_ind_sfnsf_sfn, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree *fapi_subframe_ind_sfnsf_sf_tree = proto_item_add_subtree(fapi_subframe_ind_sfnsf_item, ett_fapi_subframe_ind_sfnsf_sf);
        proto_tree_add_item(fapi_subframe_ind_sfnsf_sf_tree, hf_fapi_subframe_ind_sfnsf_sf, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 2;

        return tvb_captured_length(tvb);
}

static int dissect_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_, guint8 pdu_size _U_) 
{
    proto_item *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item = proto_tree_add_item(tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a, tvb, offset, pdu_size, ENC_NA);

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlevel_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlvl);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlevel_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlvl, tvb, offset, 1, ENC_NA);

    offset += 1;
    
    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment, tvb, offset, 1, ENC_NA);

    offset += 1;
     
    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs_1_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs_1_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_redundancyversion_1_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rv);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_redundancyversion_1_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rv, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding, tvb, offset, 4, ENC_BIG_ENDIAN);

    offset += 4;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi_1_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi_1_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_dai_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_dai);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_dai_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_dai, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower);

    proto_item *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower_item =
	    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower, tvb, offset, 2, ENC_BIG_ENDIAN);
    gint16 txPower = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_item_append_text(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower_item, " (%g dBm)", (float)(txPower - 6000)/1000);

    offset += 2;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_padding_tree = 
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_padding);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_padding_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_padding, tvb, offset, 2, ENC_NA);

    offset += 2;

    return tvb_captured_length(tvb);
}

static int dissect_fapi_dlconfig_req_pdu_info_pduunion_dcipdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_, guint8 pdu_size _U_)
{
    guint8 dciFormat = tvb_get_guint8(tvb, offset);

    proto_item *fapi_dlconfig_pdu_info_pduunion_dcipdu_item = proto_tree_add_item(tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu, tvb, offset, pdu_size, ENC_NA);

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dciformat_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dciformat);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dciformat_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dciformat, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_cceindex_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_cceIndex);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_cceindex_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_cceIndex, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_rnti_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_rnti);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_rnti_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_rnti, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 2;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu);

    proto_item *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_item = 
	    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu, tvb, offset, pdu_size - 4, ENC_NA);

    switch (dciFormat) {
	case 1: {
	    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_tree = 
		    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a);
	    dissect_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a(tvb, pinfo, fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1a_tree, data, offset, pdu_size - offset);
	}
	break;
    }

    return tvb_captured_length(tvb);
}

static int dissect_fapi_dlconfig_pdu_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_)
{
    guint8 pdu_type = 0;
    guint8 pdu_size = 0;

    pdu_size = tvb_get_guint8(tvb, offset + 1);

    proto_item *fapi_dlconfig_pdu_info_item = proto_tree_add_item(tree, hf_fapi_dlconfig_req_pdu_info, tvb, offset, pdu_size, ENC_NA);

    proto_tree *fapi_dlconfig_pdu_info_pdu_type_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_item, ett_fapi_dlconfig_req_pdu_info_pdutype);
    proto_tree_add_item(fapi_dlconfig_pdu_info_pdu_type_tree, hf_fapi_dlconfig_req_pdu_info_pdutype, tvb, offset, 1, ENC_NA);

    pdu_type = tvb_get_guint8(tvb, offset);

    proto_item_append_text(fapi_dlconfig_pdu_info_item, " (%s) ", val_to_str_const(pdu_type, dlconfig_req_pdutype_vals, "Unknown (0x%02x)"));

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pdu_size_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_item, ett_fapi_dlconfig_req_pdu_info_pdusize);
    proto_tree_add_item(fapi_dlconfig_pdu_info_pdu_size_tree, hf_fapi_dlconfig_req_pdu_info_pdusize, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pdu_padding_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_item, ett_fapi_dlconfig_req_pdu_info_pdupadding);
    proto_tree_add_item(fapi_dlconfig_pdu_info_pdu_padding_tree, hf_fapi_dlconfig_req_pdu_info_pdupadding, tvb, offset, 2, ENC_NA);

    offset += 2;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_item, ett_fapi_dlconfig_req_pdu_info_pduunion);
    proto_item *fapi_dlconfig_pdu_info_pduunion_item = proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_tree, hf_fapi_dlconfig_req_pdu_info_pduunion, tvb, offset, pdu_size - 4, ENC_NA);

    switch (pdu_type) {
	    case 0: {
                proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu);
	        dissect_fapi_dlconfig_req_pdu_info_pduunion_dcipdu(tvb, pinfo, fapi_dlconfig_pdu_info_pduunion_dcipdu_tree, data, offset, pdu_size - 4);
	    }
	    break;
	    default:
		    break;
    } /* switch (pdu_type) */

    offset += (pdu_size - 4);

    return tvb_captured_length(tvb);
}
 

static int dissect_fapi_dlconfig_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_) 
{
	guint16 txPowerForPCFICH;
        guint16 i;
	guint16 numOfPDU;
	guint16 dlconfig_len = 0;


	dlconfig_len = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);

        proto_item *fapi_dlconfig_req_item = proto_tree_add_item(tree, hf_fapi_dlconfig_req, tvb, offset, dlconfig_len, ENC_NA);

        proto_tree *fapi_dlconfig_req_sfnsf_tree = proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_subframe_ind_sfnsf);

        dissect_fapi_subframe_sfnsf(tvb, pinfo, fapi_dlconfig_req_sfnsf_tree, data, offset);

	offset += 2;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_len);
        proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        
        offset += 2;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_cfi);
        proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_cfi, tvb, offset, 1, ENC_NA);

        offset += 1;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_numDCI);
        proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_numDCI, tvb, offset, 1, ENC_NA);

        offset += 1;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_numOfPDU);
        proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_numOfPDU, tvb, offset, 2, ENC_BIG_ENDIAN);

        numOfPDU = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

        offset += 2;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_txPowerForPCFICH);
        proto_item *fapi_dlconfig_req_txPowerForPCFICH_item = 
                proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_txPowerForPCFICH, tvb, offset, 2, ENC_BIG_ENDIAN);

        txPowerForPCFICH =  tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_item_append_text(fapi_dlconfig_req_txPowerForPCFICH_item, " (%g dBm)", (float)(txPowerForPCFICH - 6000)/1000);

        offset += 2;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_numOfPDSCHRNTI);
        proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_numOfPDSCHRNTI, tvb, offset, 1, ENC_NA);

        offset += 1;

        proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_padding);
        proto_tree_add_item(fapi_dlconfig_req_item, hf_fapi_dlconfig_req_padding, tvb, offset, 1, ENC_NA);

        offset += 1;
        
        for (i = 0; i < numOfPDU; i++) {
            proto_tree *fapi_dlconfig_req_pdu_info_tree = proto_item_add_subtree(fapi_dlconfig_req_item, ett_fapi_dlconfig_req_pdu_info);

	    guint8 pdu_size = tvb_get_guint8(tvb, offset + 1);

            dissect_fapi_dlconfig_pdu_info(tvb, pinfo, fapi_dlconfig_req_pdu_info_tree, data, offset);

	    offset += pdu_size;
        }

	/* 
	 * There seems to be an issue with encoding of the size of dl config request
	 *
	 * if (numOfPDU) offset += 4; 
	 */
        return tvb_captured_length(tvb);
}
 
static int dissect_fapi_subframe_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_)
{
        proto_item *fapi_subframe_ind_item = proto_tree_add_item(tree, hf_fapi_subframe_ind, tvb, offset, 4, ENC_NA);

        proto_tree *fapi_subframe_ind_sfnsf_tree = proto_item_add_subtree(fapi_subframe_ind_item, ett_fapi_subframe_ind_sfnsf);

        dissect_fapi_subframe_sfnsf(tvb, pinfo, fapi_subframe_ind_sfnsf_tree, data, offset);
        /*
        proto_item *fapi_subframe_ind_sfnsf_item = proto_tree_add_item(fapi_subframe_ind_sfnsf_tree, hf_fapi_subframe_ind_sfnsf, tvb, offset, 2, ENC_NA);

        proto_tree *fapi_subframe_ind_sfnsf_sfn_tree = proto_item_add_subtree(fapi_subframe_ind_sfnsf_item, ett_fapi_subframe_ind_sfnsf_sfn);
        proto_tree_add_item(fapi_subframe_ind_sfnsf_sfn_tree, hf_fapi_subframe_ind_sfnsf_sfn, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree *fapi_subframe_ind_sfnsf_sf_tree = proto_item_add_subtree(fapi_subframe_ind_sfnsf_item, ett_fapi_subframe_ind_sfnsf_sf);
        proto_tree_add_item(fapi_subframe_ind_sfnsf_sf_tree, hf_fapi_subframe_ind_sfnsf_sf, tvb, offset, 2, ENC_BIG_ENDIAN);

         */
        offset += 2;

        proto_tree *fapi_subframe_ind_padding_tree = proto_item_add_subtree(fapi_subframe_ind_item, ett_fapi_subframe_ind_padding);
        proto_tree_add_item(fapi_subframe_ind_padding_tree, hf_fapi_subframe_ind_padding, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 2;

        return tvb_captured_length(tvb);
}
static int dissect_fapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    guint8 msg_id = tvb_get_guint8(tvb, 0);
    guint     offset = 0;
    guint8 last_msg_id = 0xff;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FAPI");
    col_clear(pinfo->cinfo,COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", "FAPI Bundle");

     while (last_msg_id != msg_id) {
    
        const gchar* message_str = val_to_str_const(msg_id, message_id_vals, "Unknown (0x%02x)");
    
        guint16 msg_len = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);
    
        proto_item *fapi_message_item = proto_tree_add_item(tree, proto_fapi, tvb, offset, msg_len + 4, ENC_NA); // 4 bytes for header
    
        proto_item_append_text(fapi_message_item, " (%s)", message_str); /* sneak peek */
     
        proto_tree *fapi_message_type = proto_item_add_subtree(fapi_message_item, ett_fapi_message_type);
        proto_tree_add_item(fapi_message_type, hf_fapi_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    
        proto_tree *fapi_message_vendor_tlv_len = proto_item_add_subtree(fapi_message_item, ett_fapi_message_vendor_tlv_len);
        proto_tree_add_item(fapi_message_vendor_tlv_len, hf_fapi_message_vendor_tlv_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    
        proto_tree *fapi_message_len = proto_item_add_subtree(fapi_message_item, ett_fapi_message_len);
        proto_tree_add_item(fapi_message_len, hf_fapi_message_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    
        offset += 2;
    
        proto_tree *fapi_message_body = proto_item_add_subtree(fapi_message_item, ett_fapi_message_body);
        /*
         */
        switch (msg_id) {
            case 0x80:
                    dissect_fapi_dlconfig_req(tvb, pinfo, fapi_message_body, data, offset);
                    break;
            case 0x82:
                    dissect_fapi_subframe_ind(tvb, pinfo, fapi_message_body, data, offset);
                    break;
            default: {
                    proto_item *fapi_message_body_item = proto_tree_add_item(fapi_message_body, hf_fapi_message_body, tvb, offset, msg_len, ENC_NA);

                    proto_item_add_subtree(fapi_message_body_item, ett_fapi_message_body);
            }
            break;
        } 

        offset += msg_len;

        last_msg_id = msg_id;

        msg_id = tvb_get_guint8(tvb, offset);
    } 

    return tvb_captured_length(tvb);
}

void
proto_register_fapi(void)
{
    static hf_register_info hf[] = {
        { &hf_fapi_message_type, {"type", "fapi.message_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_message_vendor_tlv_len, {"vendor tlv size", "fapi.message_vendor_tlv_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL} },
        { &hf_fapi_message_len, {"size", "fapi.message_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_fapi_message_body, {"payload", "fapi.message_body", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_fapi_subframe_ind, {"subframe indication", "fapi.subframe_ind", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_subframe_ind_sfnsf, {"sfnsf", "fapi.subframe_ind.sfnsf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_subframe_ind_sfnsf_sfn, {"sfn", "fapi.subframe_ind.sfnsf.sfn", FT_UINT16, BASE_DEC, NULL, 0xfff0, NULL, HFILL } },
        { &hf_fapi_subframe_ind_sfnsf_sf, {"sf", "fapi.subframe_ind.sfnsf.sf", FT_UINT16, BASE_DEC, NULL, 0x000f, NULL, HFILL } },
        { &hf_fapi_subframe_ind_padding, {"padding", "fapi.subframe_ind.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_fapi_dlconfig_req, {"dl config request", "fapi.dlconfig_req", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_len, {"length", "fapi.dlconfig_req.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_cfi, {"cfi", "fapi.dlconfig_req.cfi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_numDCI, {"numDCI", "fapi.dlconfig_req.numDCI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_numOfPDU, {"numOfPDU", "fapi.dlconfig_req.numOfPDU", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_txPowerForPCFICH, {"txPowerForPCFICH", "fapi.dlconfig_req.txPowerForPCFICH", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_numOfPDSCHRNTI, {"numOfPDSCHRNTI", "fapi.dlconfig_req.numOfPDSCHRNTI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_fapi_dlconfig_req_padding, {"padding", "fapi.dlconfig_req.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info,{"dlConfigPDUInfo", "fapi.dlconfig_req.dlConfigPDUInfo", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pdutype, {"pduType", "fapi.dlconfig_req.dlConfigPDUInfo.pduType", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_pdutype_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pdusize, {"pduSize", "fapi.dlconfig_req.dlConfigPDUInfo.pduSize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pdupadding, {"padding", "fapi.dlconfig_req.dlConfigPDUInfo.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion, {"dlConfigPDUInfoUnion", "fapi.dlconfig_req.dlConfigPDUInfo.union", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu, {"DCIPdu", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dciformat, {"dciFormat", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciFormat", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dciformat_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_cceIndex, {"cceIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.cceIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_rnti, {"rnti", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.rnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu, {"dciPdu", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a, {"dci 1A", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlvl, {"aggregationLevel", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.aggregationLevel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment, {"vrbAssignment", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.vrbAssignment", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dci1a_vrbassignment_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs, {"mcs_1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.mcs_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rv, {"redundancyVersion_1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.redundancyVersion_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding, {"rbCoding", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.rbCoding", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi, {"newDataIndicator_1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.newDataIndicator_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc, {"harqProcessNum", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.harqProcessNum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc, {"tpc", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.tpc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_dai, {"dlAssignmentIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.dlAssignmentIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach, {"allocatePRACHFlag", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.allocatePRACHFlag", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx, {"preambleIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.preambleIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower, {"txPower", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.txPower", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx, {"PRACHMaskIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.pRACHMaskIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype, {"rntiType", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.rntiType", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dci1a_rntitype_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_padding, {"padding", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1A.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_fapi_message_type,
        &ett_fapi_message_vendor_tlv_len,
        &ett_fapi_message_len,

        &ett_fapi_message_body,

        &ett_fapi_subframe_ind,
        &ett_fapi_subframe_ind_sfnsf,
        &ett_fapi_subframe_ind_sfnsf_sfn,
        &ett_fapi_subframe_ind_sfnsf_sf,
        &ett_fapi_subframe_ind_padding,

        &ett_fapi_dlconfig_req,
        &ett_fapi_dlconfig_req_len,
        &ett_fapi_dlconfig_req_cfi,
        &ett_fapi_dlconfig_req_numDCI,
        &ett_fapi_dlconfig_req_numOfPDU,
        &ett_fapi_dlconfig_req_txPowerForPCFICH,
        &ett_fapi_dlconfig_req_numOfPDSCHRNTI,
        &ett_fapi_dlconfig_req_padding,

	&ett_fapi_dlconfig_req_pdu_info,
	&ett_fapi_dlconfig_req_pdu_info_pdutype,
	&ett_fapi_dlconfig_req_pdu_info_pdusize,
	&ett_fapi_dlconfig_req_pdu_info_pdupadding,
	&ett_fapi_dlconfig_req_pdu_info_pduunion,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dciformat,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_cceIndex,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_rnti,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_aggrlvl,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_vrbassignment,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_mcs,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rv,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rbcoding,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_ndi,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_harqproc,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_tpc,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_dai,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_allocprach,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_preambleidx,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_txpower,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_prachmaskidx,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_rntitype,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1a_padding,
    };

    proto_fapi = proto_register_protocol ("FAPI", "FAPI", "fapi");

    proto_register_field_array(proto_fapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("fapi", dissect_fapi, proto_fapi);
}

void
proto_reg_handoff_fapi(void)
{
    static dissector_handle_t fapi_handle;

    fapi_handle = create_dissector_handle(dissect_fapi, proto_fapi);

    dissector_add_uint("udp.port", FAPI_PORT_RD, fapi_handle);
    dissector_add_uint("udp.port", FAPI_PORT_WR, fapi_handle);
}
