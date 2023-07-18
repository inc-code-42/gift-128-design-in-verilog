//======================================================================//
// Author	: Inc                                                   //   
// Date		: May 23                                                //    
// Module	: gift_core.v                                           //
// Version	: v1                                                    //  
// Remarks	: v1 - Initial Draft                                    //
//                                                                      //
//======================================================================//
`timescale 1 ns/ 1 ns

module gift_128_enc(
  input wire            clk_i                  ,
  input wire            reset_n                ,

  output reg            busy                   ,
  input wire [127 : 0]  key_in                 ,
  input wire            key_ld                 ,
  output reg            key_process_done_latch ,

  input wire [127 : 0]  data_in                ,
  input wire            enc_start              ,

  output wire [127 : 0] cipher_out             ,
  output reg            cipher_done 
);

localparam GIFT128_ROUNDS = 6'd40;

localparam IDLE           = 3'd0 ;
localparam KEY_PROCESS    = 3'd1 ;
localparam RND_OP         = 3'd2 ;
localparam DONE           = 3'd3 ;

reg [2:0]   gift_enc_sreg ;
reg [2:0]   gift_enc_snxt ;
reg [127:0] key_reg       ;
reg [127:0] key_nxt       ;
reg [127:0] state_reg;
reg [127:0] state_nxt;

reg         key_load_status_reg;
reg         key_load_status_nxt;

reg [5:0]   rnd_cntr_reg;
reg [5:0]   rnd_cntr_nxt;

reg [5:0]   rc_reg;
reg [5:0]   rc_nxt;

reg [127:0] enc_subcell_state;  
reg [127:0] enc_permute_state; 
reg [127:0] enc_addkey_state ; 

reg [5:0]   key_cntr_reg     ;
reg [5:0]   key_cntr_nxt     ;

reg         key_process_done ;
reg         key_update       ;

reg [127:0] rnd_key          ;

assign cipher_out  = state_reg;

always @(posedge clk_i, negedge reset_n) begin
  if (!reset_n) begin
    gift_enc_sreg          <= IDLE;
    key_reg                <= 'd0;
    state_reg              <= 'd0;
    rc_reg                 <= 'd0;
    rnd_cntr_reg           <= 'd0;
    key_cntr_reg           <= 'd0;
    key_process_done_latch <= 1'b0; 
  end
  else begin
    gift_enc_sreg          <= gift_enc_snxt; 
    key_reg                <= key_nxt;
    state_reg              <= (enc_start) ? data_in : state_nxt;
    rnd_cntr_reg           <= rnd_cntr_nxt; 
    rc_reg                 <= rc_nxt; 
    key_cntr_reg           <= key_cntr_nxt;
    key_process_done_latch <= (key_ld) ? 1'b0 : (key_process_done) ? 1'b1 : key_process_done_latch;
  end
end


always @* begin
  gift_enc_snxt     = gift_enc_sreg;
  key_nxt           = key_reg;
  state_nxt         = state_reg;
  rc_nxt            = rc_reg;
  rnd_cntr_nxt      = rnd_cntr_reg;
  busy              = 1'b0;
  cipher_done       = 1'b0;
  enc_subcell_state = 'd0;
  enc_permute_state = 'd0;
  enc_addkey_state  = 'd0;
  key_cntr_nxt      = key_cntr_reg;
  key_update        = 1'b0;
  key_process_done  = 1'b0;
  rnd_key           = 'd0;
  case(gift_enc_sreg)
    IDLE: begin
      if (key_ld) begin
        gift_enc_snxt = KEY_PROCESS;
        key_nxt       = key_in;
        key_cntr_nxt  = 'd0;
        busy          = 1'b1;	
      end	      
      else if (enc_start) begin
        gift_enc_snxt = RND_OP;
        rnd_cntr_nxt  = 'd0;
	busy          = 1'b1;
	rc_nxt        = 'd0;
      end	      
    end
    KEY_PROCESS: begin
      key_cntr_nxt      = key_cntr_reg + 1'b1;	    
      key_nxt           = (key_reg == 'd0) ? key_reg: UpdateKey(key_reg);
      key_update        = 1'b1;
      gift_enc_snxt     = (key_cntr_nxt == 'd40) ? IDLE: KEY_PROCESS;
      key_process_done  = (gift_enc_snxt == IDLE) ? 1'b1 : 1'b0;
      busy              = 1'b1;
    end
    RND_OP: begin
      busy              = 1'b1;
      rc_nxt            = UpdateConstant(rc_reg);
      rnd_key           = key_storage[rnd_cntr_reg];

      enc_subcell_state = SubCells(state_reg);                             // Sbox
      enc_permute_state = PermBits(enc_subcell_state);                     // pbox
      enc_addkey_state  = AddRoundKey(enc_permute_state, rnd_key, rc_nxt); // add-rnd key
      state_nxt         = enc_addkey_state;

      rnd_cntr_nxt      = rnd_cntr_reg + 1'b1; 
      gift_enc_snxt     = (rnd_cntr_nxt == GIFT128_ROUNDS) ? DONE: RND_OP;
    end
    DONE: begin
      gift_enc_snxt     = IDLE;
      busy              = 1'b1;
      cipher_done       = 1'b1;
    end    
  endcase
end

//----------------------------------------------------
// Key Generation Process
//----------------------------------------------------
reg [127:0] key_storage [0:39];

integer k;

always @(posedge clk_i, negedge reset_n) begin
  if (!reset_n) begin
    for (k=1;k<40;k=k+1) begin
      key_storage [k] <= 'd0;
    end
  end else begin
    if (key_update) begin
      key_storage [key_cntr_reg] <= key_reg;	    
    end	    
  end
end

function [3 : 0] gs(input [3 : 0] x); begin
    gs          = 'd0;
    case (x)
      4'h0 : gs = 4'h1;
      4'h1 : gs = 4'ha;
      4'h2 : gs = 4'h4;
      4'h3 : gs = 4'hc;
      4'h4 : gs = 4'h6;
      4'h5 : gs = 4'hf;
      4'h6 : gs = 4'h3;
      4'h7 : gs = 4'h9;
      4'h8 : gs = 4'h2;
      4'h9 : gs = 4'hd;
      4'ha : gs = 4'hb;
      4'hb : gs = 4'h7;
      4'hc : gs = 4'h5;
      4'hd : gs = 4'h0;
      4'he : gs = 4'h8;
      4'hf : gs = 4'he;
    endcase 
  end
endfunction


function [127 : 0] SubCells(input [127 : 0] x); begin
    SubCells[003 : 000] = gs(x[003 : 000]);
    SubCells[007 : 004] = gs(x[007 : 004]);
    SubCells[011 : 008] = gs(x[011 : 008]);
    SubCells[015 : 012] = gs(x[015 : 012]);
    SubCells[019 : 016] = gs(x[019 : 016]);
    SubCells[023 : 020] = gs(x[023 : 020]);
    SubCells[027 : 024] = gs(x[027 : 024]);
    SubCells[031 : 028] = gs(x[031 : 028]);

    SubCells[035 : 032] = gs(x[035 : 032]);
    SubCells[039 : 036] = gs(x[039 : 036]);
    SubCells[043 : 040] = gs(x[043 : 040]);
    SubCells[047 : 044] = gs(x[047 : 044]);
    SubCells[051 : 048] = gs(x[051 : 048]);
    SubCells[055 : 052] = gs(x[055 : 052]);
    SubCells[059 : 056] = gs(x[059 : 056]);
    SubCells[063 : 060] = gs(x[063 : 060]);

    SubCells[067 : 064] = gs(x[067 : 064]);
    SubCells[071 : 068] = gs(x[071 : 068]);
    SubCells[075 : 072] = gs(x[075 : 072]);
    SubCells[079 : 076] = gs(x[079 : 076]);
    SubCells[083 : 080] = gs(x[083 : 080]);
    SubCells[087 : 084] = gs(x[087 : 084]);
    SubCells[091 : 088] = gs(x[091 : 088]);
    SubCells[095 : 092] = gs(x[095 : 092]);

    SubCells[099 : 096] = gs(x[099 : 096]);
    SubCells[103 : 100] = gs(x[103 : 100]);
    SubCells[107 : 104] = gs(x[107 : 104]);
    SubCells[111 : 108] = gs(x[111 : 108]);
    SubCells[115 : 112] = gs(x[115 : 112]);
    SubCells[119 : 116] = gs(x[119 : 116]);
    SubCells[123 : 120] = gs(x[123 : 120]);
    SubCells[127 : 124] = gs(x[127 : 124]);
  end
endfunction


function [127 : 0] PermBits(input [127 : 0] x); begin
    PermBits[000] = x[000];
    PermBits[033] = x[001];
    PermBits[066] = x[002];
    PermBits[099] = x[003];
    PermBits[096] = x[004];
    PermBits[001] = x[005];
    PermBits[034] = x[006];
    PermBits[067] = x[007];
    PermBits[064] = x[008];
    PermBits[097] = x[009];
    PermBits[002] = x[010];
    PermBits[035] = x[011];
    PermBits[032] = x[012];
    PermBits[065] = x[013];
    PermBits[098] = x[014];
    PermBits[003] = x[015];

    PermBits[004] = x[016];
    PermBits[037] = x[017];
    PermBits[070] = x[018];
    PermBits[103] = x[019];
    PermBits[100] = x[020];
    PermBits[005] = x[021];
    PermBits[038] = x[022];
    PermBits[071] = x[023];
    PermBits[068] = x[024];
    PermBits[101] = x[025];
    PermBits[006] = x[026];
    PermBits[039] = x[027];
    PermBits[036] = x[028];
    PermBits[069] = x[029];
    PermBits[102] = x[030];
    PermBits[007] = x[031];

    PermBits[008] = x[032];
    PermBits[041] = x[033];
    PermBits[074] = x[034];
    PermBits[107] = x[035];
    PermBits[104] = x[036];
    PermBits[009] = x[037];
    PermBits[042] = x[038];
    PermBits[075] = x[039];
    PermBits[072] = x[040];
    PermBits[105] = x[041];
    PermBits[010] = x[042];
    PermBits[043] = x[043];
    PermBits[040] = x[044];
    PermBits[073] = x[045];
    PermBits[106] = x[046];
    PermBits[011] = x[047];

    PermBits[012] = x[048];
    PermBits[045] = x[049];
    PermBits[078] = x[050];
    PermBits[111] = x[051];
    PermBits[108] = x[052];
    PermBits[013] = x[053];
    PermBits[046] = x[054];
    PermBits[079] = x[055];
    PermBits[076] = x[056];
    PermBits[109] = x[057];
    PermBits[014] = x[058];
    PermBits[047] = x[059];
    PermBits[044] = x[060];
    PermBits[077] = x[061];
    PermBits[110] = x[062];
    PermBits[015] = x[063];

    PermBits[016] = x[064];
    PermBits[049] = x[065];
    PermBits[082] = x[066];
    PermBits[115] = x[067];
    PermBits[112] = x[068];
    PermBits[017] = x[069];
    PermBits[050] = x[070];
    PermBits[083] = x[071];
    PermBits[080] = x[072];
    PermBits[113] = x[073];
    PermBits[018] = x[074];
    PermBits[051] = x[075];
    PermBits[048] = x[076];
    PermBits[081] = x[077];
    PermBits[114] = x[078];
    PermBits[019] = x[079];

    PermBits[020] = x[080];
    PermBits[053] = x[081];
    PermBits[086] = x[082];
    PermBits[119] = x[083];
    PermBits[116] = x[084];
    PermBits[021] = x[085];
    PermBits[054] = x[086];
    PermBits[087] = x[087];
    PermBits[084] = x[088];
    PermBits[117] = x[089];
    PermBits[022] = x[090];
    PermBits[055] = x[091];
    PermBits[052] = x[092];
    PermBits[085] = x[093];
    PermBits[118] = x[094];
    PermBits[023] = x[095];

    PermBits[024] = x[096];
    PermBits[057] = x[097];
    PermBits[090] = x[098];
    PermBits[123] = x[099];
    PermBits[120] = x[100];
    PermBits[025] = x[101];
    PermBits[058] = x[102];
    PermBits[091] = x[103];
    PermBits[088] = x[104];
    PermBits[121] = x[105];
    PermBits[026] = x[106];
    PermBits[059] = x[107];
    PermBits[056] = x[108];
    PermBits[089] = x[109];
    PermBits[122] = x[110];
    PermBits[027] = x[111];

    PermBits[028] = x[112];
    PermBits[061] = x[113];
    PermBits[094] = x[114];
    PermBits[127] = x[115];
    PermBits[124] = x[116];
    PermBits[029] = x[117];
    PermBits[062] = x[118];
    PermBits[095] = x[119];
    PermBits[092] = x[120];
    PermBits[125] = x[121];
    PermBits[030] = x[122];
    PermBits[063] = x[123];
    PermBits[060] = x[124];
    PermBits[093] = x[125];
    PermBits[126] = x[126];
    PermBits[031] = x[127];
  end
endfunction


function [127 : 0] AddRoundKey(input [127 : 0] state,
                               input [127 : 0] k,
                               input [5 : 0]   rc); begin: ark 
    reg [31 : 0] u;
    reg [31 : 0] v;
    reg [127 : 0] s;
    integer i;

    u = k[095 : 064];
    v = k[031 : 000];

    s = state;
    for (i = 0 ; i < 32 ; i = i + 1) begin
      s[(4 * i + 2)] = state[(4 * i + 2)] ^ u[i];
      s[(4 * i + 1)] = state[(4 * i + 1)] ^ v[i];
    end

    s[127] = s[127] ^ 1'h1;
    s[023] = s[023] ^ rc[5];
    s[019] = s[019] ^ rc[4];
    s[015] = s[015] ^ rc[3];
    s[011] = s[011] ^ rc[2];
    s[007] = s[007] ^ rc[1];
    s[003] = s[003] ^ rc[0];

    AddRoundKey = s;
  end
endfunction


function [127 : 0] UpdateKey(input [127 : 0] k); begin: uk
    reg [15 : 0] rot12_k0;
    reg [15 : 0] rot2_k1;

    rot12_k0 = {k[011 : 000], k[015 : 012]};
    rot2_k1  = {k[017 : 016], k[031 : 018]};

    UpdateKey = {rot2_k1, rot12_k0, k[127 : 032]};

  end
endfunction


function [5 : 0] UpdateConstant(input [5 : 0] rc); begin
    UpdateConstant = {rc[4 : 0], rc[5] ^ rc[4] ^ 1'h1};
  end
endfunction



endmodule

//==============================================================================//
