//======================================================================//
// Author	: Inc                                                   //   
// Date		: May 23                                                //    
// Module	: gift_128_dec.v                                        //
// Version	: v1                                                    //  
// Remarks	: v1 - Initial Draft                                    //
//                                                                      //
//======================================================================//
`timescale 1 ns/ 1 ns

module gift_128_dec(
  input wire            clk_i                  ,
  input wire            reset_n                ,

  output reg            busy                   ,

  input wire [127 : 0]  key_in                 ,
  input wire            key_ld                 ,
  output reg            key_process_done_latch ,

  input wire [127 : 0]  cipher_in              ,
  input wire            dec_start              ,

  output wire [127 : 0] plain_out              ,
  output reg            dec_done 
);

localparam GIFT128_ROUNDS = 6'd40;

localparam IDLE           = 3'd0 ;
localparam KEY_PROCESS    = 3'd1 ;
localparam RND_OP         = 3'd2 ;
localparam DONE           = 3'd3 ;

reg [2:0]   gift_dec_sreg ;
reg [2:0]   gift_dec_snxt ;
reg [127:0] key_reg  ;
reg [127:0] key_nxt  ;
reg [127:0] state_reg;
reg [127:0] state_nxt;

reg         key_load_status_reg;
reg         key_load_status_nxt;

reg [5:0]   rnd_cntr_reg;
reg [5:0]   rnd_cntr_nxt;

reg [5:0]   rc_reg;
reg [5:0]   rc_nxt;

reg [127:0] dec_subcell_state;  
reg [127:0] dec_permute_state; 
reg [127:0] dec_addkey_state ; 

reg [5:0]   key_cntr_reg     ;
reg [5:0]   key_cntr_nxt     ;

reg         key_process_done ;
reg         key_update       ;

reg [127:0] rnd_key          ;


assign plain_out  = state_reg;

always @(posedge clk_i, negedge reset_n) begin
  if (!reset_n) begin
    gift_dec_sreg          <= IDLE;
    key_reg                <= 'd0;
    state_reg              <= 'd0;
    rc_reg                 <= 'd0;
    rnd_cntr_reg           <= 'd0;
    key_cntr_reg           <= 'd0;
    key_process_done_latch <= 1'b0; 
  end
  else begin
    gift_dec_sreg          <= gift_dec_snxt; 
    key_reg                <= key_nxt;
    state_reg              <= (dec_start) ? cipher_in : state_nxt;
    rnd_cntr_reg           <= rnd_cntr_nxt; 
    rc_reg                 <= rc_nxt; 
    key_cntr_reg           <= key_cntr_nxt; 
    key_process_done_latch <= (key_ld) ? 1'b0 : (key_process_done) ? 1'b1 : key_process_done_latch; 
  end
end


always @* begin
  gift_dec_snxt     = gift_dec_sreg;
  key_nxt           = key_reg;
  state_nxt         = state_reg;
  rc_nxt            = rc_reg;
  rnd_cntr_nxt      = rnd_cntr_reg;
  busy              = 1'b0;
  dec_done          = 1'b0;
  dec_subcell_state = 'd0;
  dec_permute_state = 'd0;
  dec_addkey_state  = 'd0;
  key_cntr_nxt      = key_cntr_reg;
  key_update        = 1'b0;
  key_process_done  = 1'b0;
  rnd_key           = 'd0;
  case(gift_dec_sreg)
    IDLE: begin
      if (key_ld) begin
        gift_dec_snxt = KEY_PROCESS;
	key_nxt       = key_in;
        key_cntr_nxt  = 'd0;	    
	busy          = 1'b1;
      end
      else if (dec_start) begin
        gift_dec_snxt = RND_OP;
        rnd_cntr_nxt  = 'd39;
	busy          = 1'b1;
	rc_nxt        = 'd0;
      end	      
    end
    KEY_PROCESS: begin
      key_cntr_nxt      = key_cntr_reg + 1'b1;	    
      key_nxt           = (key_reg == 'd0) ? key_reg: InvUpdateKey(key_reg);
      key_update        = 1'b1;
      gift_dec_snxt     = (key_cntr_nxt == 'd40) ? IDLE: KEY_PROCESS;
      key_process_done  = (gift_dec_snxt == IDLE) ? 1'b1 : 1'b0;
      busy              = 1'b1;
    end
    RND_OP: begin
      busy              = 1'b1;
      rnd_key           = key_storage [rnd_cntr_reg];       
      dec_addkey_state  = InvAddRoundKey(state_reg, rnd_key, InvUpdateConstant(rnd_cntr_reg)); // add-rnd key
      dec_permute_state = InvPermBits(dec_addkey_state);                                       // pbox
      dec_subcell_state = InvSubCells(dec_permute_state);                                      // Sbox
      state_nxt         = dec_subcell_state;
      rnd_cntr_nxt      = rnd_cntr_reg - 1'b1; 
      rc_nxt            = rnd_cntr_nxt;
      gift_dec_snxt     = (rnd_cntr_reg == 'd0) ? DONE: RND_OP;
    end
    DONE: begin
      gift_dec_snxt     = IDLE;
      busy              = 1'b1;
      dec_done          = 1'b1;
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

function [3 : 0] inv_gs(input [3 : 0] x); begin
  case (x)
    4'h0 : inv_gs = 4'hd;
    4'h1 : inv_gs = 4'h0;
    4'h2 : inv_gs = 4'h8;
    4'h3 : inv_gs = 4'h6;
    4'h4 : inv_gs = 4'h2;
    4'h5 : inv_gs = 4'hc;
    4'h6 : inv_gs = 4'h4;
    4'h7 : inv_gs = 4'hb;
    4'h8 : inv_gs = 4'he;
    4'h9 : inv_gs = 4'h7;
    4'ha : inv_gs = 4'h1;
    4'hb : inv_gs = 4'ha;
    4'hc : inv_gs = 4'h3;
    4'hd : inv_gs = 4'h9;
    4'he : inv_gs = 4'hf;
    4'hf : inv_gs = 4'h5;
  endcase // case (x)
end
endfunction // inv_gs


function [127 : 0] InvSubCells(input [127 : 0] x); begin
    InvSubCells[003 : 000] = inv_gs(x[003 : 000]);
    InvSubCells[007 : 004] = inv_gs(x[007 : 004]);
    InvSubCells[011 : 008] = inv_gs(x[011 : 008]);
    InvSubCells[015 : 012] = inv_gs(x[015 : 012]);
    InvSubCells[019 : 016] = inv_gs(x[019 : 016]);
    InvSubCells[023 : 020] = inv_gs(x[023 : 020]);
    InvSubCells[027 : 024] = inv_gs(x[027 : 024]);
    InvSubCells[031 : 028] = inv_gs(x[031 : 028]);
    InvSubCells[035 : 032] = inv_gs(x[035 : 032]);
    InvSubCells[039 : 036] = inv_gs(x[039 : 036]);
    InvSubCells[043 : 040] = inv_gs(x[043 : 040]);
    InvSubCells[047 : 044] = inv_gs(x[047 : 044]);
    InvSubCells[051 : 048] = inv_gs(x[051 : 048]);
    InvSubCells[055 : 052] = inv_gs(x[055 : 052]);
    InvSubCells[059 : 056] = inv_gs(x[059 : 056]);
    InvSubCells[063 : 060] = inv_gs(x[063 : 060]);
    InvSubCells[067 : 064] = inv_gs(x[067 : 064]);
    InvSubCells[071 : 068] = inv_gs(x[071 : 068]);
    InvSubCells[075 : 072] = inv_gs(x[075 : 072]);
    InvSubCells[079 : 076] = inv_gs(x[079 : 076]);
    InvSubCells[083 : 080] = inv_gs(x[083 : 080]);
    InvSubCells[087 : 084] = inv_gs(x[087 : 084]);
    InvSubCells[091 : 088] = inv_gs(x[091 : 088]);
    InvSubCells[095 : 092] = inv_gs(x[095 : 092]);
    InvSubCells[099 : 096] = inv_gs(x[099 : 096]);
    InvSubCells[103 : 100] = inv_gs(x[103 : 100]);
    InvSubCells[107 : 104] = inv_gs(x[107 : 104]);
    InvSubCells[111 : 108] = inv_gs(x[111 : 108]);
    InvSubCells[115 : 112] = inv_gs(x[115 : 112]);
    InvSubCells[119 : 116] = inv_gs(x[119 : 116]);
    InvSubCells[123 : 120] = inv_gs(x[123 : 120]);
    InvSubCells[127 : 124] = inv_gs(x[127 : 124]);
  end
endfunction // InvSubCells


function [127 : 0] InvPermBits(input [127 : 0] x); begin
    InvPermBits[000] = x[000];
    InvPermBits[001] = x[033];
    InvPermBits[002] = x[066];
    InvPermBits[003] = x[099];
    InvPermBits[004] = x[096];
    InvPermBits[005] = x[001];
    InvPermBits[006] = x[034];
    InvPermBits[007] = x[067];
    InvPermBits[008] = x[064];
    InvPermBits[009] = x[097];
    InvPermBits[010] = x[002];
    InvPermBits[011] = x[035];
    InvPermBits[012] = x[032];
    InvPermBits[013] = x[065];
    InvPermBits[014] = x[098];
    InvPermBits[015] = x[003];
    InvPermBits[016] = x[004];
    InvPermBits[017] = x[037];
    InvPermBits[018] = x[070];
    InvPermBits[019] = x[103];
    InvPermBits[020] = x[100];
    InvPermBits[021] = x[005];
    InvPermBits[022] = x[038];
    InvPermBits[023] = x[071];
    InvPermBits[024] = x[068];
    InvPermBits[025] = x[101];
    InvPermBits[026] = x[006];
    InvPermBits[027] = x[039];
    InvPermBits[028] = x[036];
    InvPermBits[029] = x[069];
    InvPermBits[030] = x[102];
    InvPermBits[031] = x[007];
    InvPermBits[032] = x[008];
    InvPermBits[033] = x[041];
    InvPermBits[034] = x[074];
    InvPermBits[035] = x[107];
    InvPermBits[036] = x[104];
    InvPermBits[037] = x[009];
    InvPermBits[038] = x[042];
    InvPermBits[039] = x[075];
    InvPermBits[040] = x[072];
    InvPermBits[041] = x[105];
    InvPermBits[042] = x[010];
    InvPermBits[043] = x[043];
    InvPermBits[044] = x[040];
    InvPermBits[045] = x[073];
    InvPermBits[046] = x[106];
    InvPermBits[047] = x[011];
    InvPermBits[048] = x[012];
    InvPermBits[049] = x[045];
    InvPermBits[050] = x[078];
    InvPermBits[051] = x[111];
    InvPermBits[052] = x[108];
    InvPermBits[053] = x[013];
    InvPermBits[054] = x[046];
    InvPermBits[055] = x[079];
    InvPermBits[056] = x[076];
    InvPermBits[057] = x[109];
    InvPermBits[058] = x[014];
    InvPermBits[059] = x[047];
    InvPermBits[060] = x[044];
    InvPermBits[061] = x[077];
    InvPermBits[062] = x[110];
    InvPermBits[063] = x[015];
    InvPermBits[064] = x[016];
    InvPermBits[065] = x[049];
    InvPermBits[066] = x[082];
    InvPermBits[067] = x[115];
    InvPermBits[068] = x[112];
    InvPermBits[069] = x[017];
    InvPermBits[070] = x[050];
    InvPermBits[071] = x[083];
    InvPermBits[072] = x[080];
    InvPermBits[073] = x[113];
    InvPermBits[074] = x[018];
    InvPermBits[075] = x[051];
    InvPermBits[076] = x[048];
    InvPermBits[077] = x[081];
    InvPermBits[078] = x[114];
    InvPermBits[079] = x[019];
    InvPermBits[080] = x[020];
    InvPermBits[081] = x[053];
    InvPermBits[082] = x[086];
    InvPermBits[083] = x[119];
    InvPermBits[084] = x[116];
    InvPermBits[085] = x[021];
    InvPermBits[086] = x[054];
    InvPermBits[087] = x[087];
    InvPermBits[088] = x[084];
    InvPermBits[089] = x[117];
    InvPermBits[090] = x[022];
    InvPermBits[091] = x[055];
    InvPermBits[092] = x[052];
    InvPermBits[093] = x[085];
    InvPermBits[094] = x[118];
    InvPermBits[095] = x[023];
    InvPermBits[096] = x[024];
    InvPermBits[097] = x[057];
    InvPermBits[098] = x[090];
    InvPermBits[099] = x[123];
    InvPermBits[100] = x[120];
    InvPermBits[101] = x[025];
    InvPermBits[102] = x[058];
    InvPermBits[103] = x[091];
    InvPermBits[104] = x[088];
    InvPermBits[105] = x[121];
    InvPermBits[106] = x[026];
    InvPermBits[107] = x[059];
    InvPermBits[108] = x[056];
    InvPermBits[109] = x[089];
    InvPermBits[110] = x[122];
    InvPermBits[111] = x[027];
    InvPermBits[112] = x[028];
    InvPermBits[113] = x[061];
    InvPermBits[114] = x[094];
    InvPermBits[115] = x[127];
    InvPermBits[116] = x[124];
    InvPermBits[117] = x[029];
    InvPermBits[118] = x[062];
    InvPermBits[119] = x[095];
    InvPermBits[120] = x[092];
    InvPermBits[121] = x[125];
    InvPermBits[122] = x[030];
    InvPermBits[123] = x[063];
    InvPermBits[124] = x[060];
    InvPermBits[125] = x[093];
    InvPermBits[126] = x[126];
    InvPermBits[127] = x[031];
  end
endfunction // InvPermBits


function [127 : 0] InvAddRoundKey(input [127 : 0] state,
                                  input [127 : 0] k,
                                  input [5 : 0]   rc);
  begin : ark
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

    InvAddRoundKey = s;
  end
endfunction // InvAddRoundkey


function [127 : 0] InvUpdateKey(input [127 : 0] k);
  begin : udk
    reg [15 : 0] rot12_k0;
    reg [15 : 0] rot2_k1;

    rot12_k0 = {k[011 : 000], k[015 : 012]};
    rot2_k1  = {k[017 : 016], k[031 : 018]};

    InvUpdateKey = {rot2_k1, rot12_k0, k[127 : 032]};
  end
endfunction // InvUpdateKey

function [5 : 0] InvUpdateConstant(input [5 : 0] round);
  begin : irc
    reg [5 : 0] rc;
    case (round)
      00 : rc = 6'h01;
      01 : rc = 6'h03;
      02 : rc = 6'h07;
      03 : rc = 6'h0f;
      04 : rc = 6'h1f;
      05 : rc = 6'h3e;
      06 : rc = 6'h3d;
      07 : rc = 6'h3b;
      08 : rc = 6'h37;
      09 : rc = 6'h2f;
      10 : rc = 6'h1e;
      11 : rc = 6'h3c;
      12 : rc = 6'h39;
      13 : rc = 6'h33;
      14 : rc = 6'h27;
      15 : rc = 6'h0e;
      16 : rc = 6'h1d;
      17 : rc = 6'h3a;
      18 : rc = 6'h35;
      19 : rc = 6'h2b;
      20 : rc = 6'h16;
      21 : rc = 6'h2c;
      22 : rc = 6'h18;
      23 : rc = 6'h30;
      24 : rc = 6'h21;
      25 : rc = 6'h02;
      26 : rc = 6'h05;
      27 : rc = 6'h0b;
      28 : rc = 6'h17;
      29 : rc = 6'h2e;
      30 : rc = 6'h1c;
      31 : rc = 6'h38;
      32 : rc = 6'h31;
      33 : rc = 6'h23;
      34 : rc = 6'h06;
      35 : rc = 6'h0d;
      36 : rc = 6'h1b;
      37 : rc = 6'h36;
      38 : rc = 6'h2d;
      39 : rc = 6'h1a;
      default : rc = 6'h0;
    endcase // case (round)
    InvUpdateConstant = rc;
  end
endfunction // InvUpdateConstant


endmodule

//-----------------------------------------------------------------------------------------//
