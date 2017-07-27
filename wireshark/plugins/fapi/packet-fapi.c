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

static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlvl					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype				= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_mcs 						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rv						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_ndi						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_tpc						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_dai						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_txpower					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_padding					= -1;

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

static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pdulen						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pduidx						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rnti							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_resallocationtype					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_vrbassignment					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rbcoding						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_mcs							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rv							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transportblocks					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_tb2cwswapflag					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transmissionscheme					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numlayers						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numsubbands						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_uecategory						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pa							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex				= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_ngap							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_nprb							= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numrbpersubband					= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numbfVector						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_subbandInfo						= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo				= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx			= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna			= -1;
static int hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna		= -1;

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

static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlvl 		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype 	= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_mcs 		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rv			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_ndi			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_tpc			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_dai			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_txpower		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype		= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_padding		= -1;

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

static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu							= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pdulen						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pduidx						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rnti						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_resallocationtype					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_vrbassignment					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rbcoding						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_mcs						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rv							= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transportblocks					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_tb2cwswapflag					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transmissionscheme					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numlayers						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numsubbands					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_uecategory						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pa							= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex				= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_ngap						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_nprb						= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numrbpersubband					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numbfVector					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_subbandInfo					= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo				= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna			= -1;
static gint ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna		= -1;

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

static const value_string dlconfig_req_dci1_resallocationtype_vals[] = {
	{0, "Type 0"},
	{1, "Type 1"},
	{2, "Type 2"},
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

static const value_string dlconfig_req_dlsch_txscheme_vals[] = {
	{0, "Single Antenna Port 0"},
	{1, "Transmit Diversity"},
	{2, "Large Delay CDD"},
	{3, "Closed Loop Spatial Multiplexing"},
	{4, "Multi-User MIMO"},
	{5, "Closed Loop Rank 1 Precoding"},
	{6, "Single Antenna Port 5"},
};

static const value_string dlconfig_req_dlsch_pa_vals[] = {
	{0, "-6 dB"},
	{1, "-4.77 dB"},
	{2, "-3 dB"},
	{3, "-1.77 dB"},
	{4, "0 dB"},
	{5, "1 dB"},
	{6, "2 dB"},
	{7, "3 dB"},
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

static int dissect_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_, guint8 pdu_size _U_)
{
    proto_item *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item = proto_tree_add_item(tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1, tvb, offset, pdu_size, ENC_NA);

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlevel_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlvl);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlevel_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlvl, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_mcs_1_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_mcs);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_mcs_1_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_mcs, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_redundancyversion_1_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rv);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_redundancyversion_1_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rv, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding, tvb, offset, 4, ENC_BIG_ENDIAN);

    offset += 4;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_ndi_1_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_ndi);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_ndi_1_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_ndi, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_tpc_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_tpc);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_tpc_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_tpc, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_dai_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_dai);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_dai_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_dai, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_txpower_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_txpower);

    proto_item *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_txpower_item =
	    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_txpower_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_txpower, tvb, offset, 2, ENC_BIG_ENDIAN);
    gint16 txPower = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_item_append_text(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_txpower_item, " (%g dBm)", (float)(txPower - 6000)/1000);

    offset += 2;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype, tvb, offset, 1, ENC_NA);

    offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_padding_tree =
	    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_padding);

    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_padding_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_padding, tvb, offset, 1, ENC_NA);

    offset += 1;

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

static int dissect_fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint *offset)
{
    guint8 pdu_size = 2 * (tvb_get_guint8(tvb, *offset) + 1);

    proto_item *fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_item 
	    = proto_tree_add_item(tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo, tvb, *offset, pdu_size, ENC_NA);

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_item,
		    ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx);
    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx,
		    tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_item,
		    ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna);
    proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna,
		    tvb, *offset, 1, ENC_NA);

    guint8 numAntenna = tvb_get_guint8(tvb, *offset);
    *offset += 1;

    if (numAntenna) {
        proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna_item = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_item,
		    ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna);
        proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna_item, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna,
		    tvb, *offset, 2*numAntenna, ENC_NA);

	*offset += (2*numAntenna); // 16 bits per antenna
    }
    return tvb_captured_length(tvb);
}

static int dissect_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, guint offset _U_, guint8 pdu_size _U_)
{
	proto_item *fapi_dlconfig_pdu_info_pduunion_dlschpdu_item = proto_tree_add_item(tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu, tvb, offset, pdu_size, ENC_NA);

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_pdulen_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pdulen);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_pdulen_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pdulen, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_pduidx_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pduidx);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_pduidx_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pduidx, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_rnti_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rnti);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_rnti_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rnti, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_resallocationtype_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_resallocationtype);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_resallocationtype_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_resallocationtype, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_vrbassignment_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_vrbassignment);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_vrbassignment_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_vrbassignment, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_rbcoding_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rbcoding);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_rbcoding_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rbcoding, tvb, offset, 4, ENC_BIG_ENDIAN);

	offset += 4;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_mcs_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_mcs);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_mcs_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_mcs, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_rv_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rv);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_rv_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rv, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_transportblocks_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transportblocks);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_transportblocks_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transportblocks, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_tb2cwswapflag_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_tb2cwswapflag);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_tb2cwswapflag_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_tb2cwswapflag, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_transmissionscheme_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transmissionscheme);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_transmissionscheme_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transmissionscheme, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_numlayers_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numlayers);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_numlayers_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numlayers, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_numsubbands_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numsubbands);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_numsubbands_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numsubbands, tvb, offset, 1, ENC_NA);

	guint8 numSubBands = tvb_get_guint8(tvb, offset);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_uecategory_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_uecategory);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_uecategory_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_uecategory, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_pa_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pa);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_pa_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pa, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_ngap_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_ngap);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_ngap_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_ngap, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_nprb_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_nprb);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_nprb_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_nprb, tvb, offset, 1, ENC_NA);

	offset += 1;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_numrbpersubband_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numrbpersubband);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_numrbpersubband_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numrbpersubband, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_numbfvectors_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numbfVector);
	proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_numbfvectors_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numbfVector, tvb, offset, 2, ENC_BIG_ENDIAN);

	guint16 numBfVectors = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

	offset += 2;

	if (numSubBands) {

	   proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_subbandinfo_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_subbandInfo);
	   proto_tree_add_item(fapi_dlconfig_pdu_info_pduunion_dlschpdu_subbandinfo_tree, hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_subbandInfo, tvb, offset, numSubBands, ENC_BIG_ENDIAN);

	   offset += numSubBands;
        }

	if (numBfVectors) {
	   guint16 i;
	   for (i = 0; i < numBfVectors; i++) {
                proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_bfvectors_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dlschpdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo);
		dissect_fapi_dlconfig_pdu_info_pduunion_dlschpdu_beamformingvectorinfo(tvb, pinfo, fapi_dlconfig_pdu_info_pduunion_dlschpdu_bfvectors_tree, data, &offset);
	   }
	}
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
	case 0: {
	    proto_tree *fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_tree =
		    proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1);
	    dissect_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1(tvb, pinfo, fapi_dlconfig_pdu_info_pduunion_dcipdu_dcipdu_1_tree, data, offset, pdu_size - offset);
	}
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
	    case 3: {
                proto_tree *fapi_dlconfig_pdu_info_pduunion_dlschpdu_tree = proto_item_add_subtree(fapi_dlconfig_pdu_info_pduunion_item, ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu);
	        dissect_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu(tvb, pinfo, fapi_dlconfig_pdu_info_pduunion_dlschpdu_tree, data, offset, pdu_size - 4);
	    }
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

	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1, {"dci 1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlvl, {"aggregationLevel", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.aggregationLevel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype, {"resAllocationType", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.vrbAssignment", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dci1_resallocationtype_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_mcs, {"mcs_1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.mcs_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rv, {"redundancyVersion_1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.redundancyVersion_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding, {"rbCoding", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.rbCoding", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_ndi, {"newDataIndicator_1", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.newDataIndicator_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc, {"harqProcessNum", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.harqProcessNum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_tpc, {"tpc", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.tpc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_dai, {"dlAssignmentIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.dlAssignmentIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_txpower, {"txPower", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.txPower", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype, {"rntiType", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.rntiType", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dci1a_rntitype_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_padding, {"padding", "fapi.dlconfig_req.dlConfigPDUInfo.union.DCIPdu.dciPdu.1.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

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

	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu, {"DLSCHPdu", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pdulen, {"dlschPduLen", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.dlschPduLen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pduidx, {"pduIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.pduIndex", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rnti, {"rnti", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.rnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_resallocationtype, {"resAllocationType", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.resAllocationType", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dci1_resallocationtype_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_vrbassignment, {"vrbAssignmentFlag", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.vrbAssignmentFlag", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dci1a_vrbassignment_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rbcoding, {"rbCoding", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.rbCoding", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_mcs, {"mcs", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.mcs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rv, {"redundancyVersion", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.redundancyVersion", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transportblocks, {"transportBlocks", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.transportBlocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_tb2cwswapflag, {"tbToCodeWordSwapFlag", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.tbToCodeWordSwapFlag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transmissionscheme, {"transmissionScheme", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.transmissionScheme", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dlsch_txscheme_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numlayers, {"numOfLayers", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.numOfLayers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numsubbands, {"numOfSubBands", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.numOfSubBands", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_uecategory, {"ueCategoryCapacity", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.ueCategoryCapacity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pa, {"pA", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.pA", FT_UINT8, BASE_DEC, (const void *)&dlconfig_req_dlsch_pa_vals, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex, {"deltaPowerOffsetAIndex", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.deltaPowerOffsetAIndex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_ngap, {"nGap", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.nGap", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_nprb, {"nPRB", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.nPRB", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numrbpersubband, {"numRbPerSubBand", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.numRbPerSubBand", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numbfVector, {"numBfVector", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.numBfVector", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_subbandInfo, {"subBandInfo", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.subBandInfo", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	{ &hf_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo, {"bfVector", "fapi.dlconfig_req.dlConfigPDUInfo.union.DLSCHPdu.bfVector", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },

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

	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_aggrlvl,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_resallocationtype,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_mcs,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rv,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rbcoding,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_ndi,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_harqproc,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_tpc,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_dai,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_txpower,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_rntitype,
	&ett_fapi_dlconfig_req_pdu_info_pduunion_dcipdu_dcipdu_1_padding,

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

	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pdulen,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pduidx,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rnti,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_resallocationtype,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_vrbassignment,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rbcoding,
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_mcs,							 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_rv,							 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transportblocks,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_tb2cwswapflag,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_transmissionscheme,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numlayers,						 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numsubbands,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_uecategory,						 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_pa,							 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_deltapoweroffsetaindex,				 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_ngap,						 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_nprb,						 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numrbpersubband,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_numbfVector,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_subbandInfo,					 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo,				 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_subbandidx,			 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_numantenna,			 
  	&ett_fapi_dlconfig_req_pdu_info_pduunion_dlschpdu_beamformingvectorinfo_bfvalueperantenna,
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
