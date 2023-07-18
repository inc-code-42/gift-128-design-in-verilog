//////////////////////////////////////////////////////////////////////////////////
// Author	: Inc
// Date		: Jul 23
// Module	: gift_enc_core_controller.v
// Version	: v1
// Rev.		: Initial Draft
//                To support AES_UART MATLAB GUI, After first key loading,
//                state machine will just wait for key loading and will not
//                forward to gift for further processing. This is just dummy
//                state
//
//
//
//
//
//////////////////////////////////////////////////////////////////////////////////
`timescale 1 ns/ 1 ps

module gift_enc_core_controller (
  input wire          clk_i           ,
  input wire          reset_n         ,

  input wire          key_input_valid ,
  input wire [127:0]  key_input       ,

  input wire          data_input_valid,
  input wire [127:0]  data_input      ,

  output wire         cipher_out_valid,
  output wire[127:0]  cipher_out
);


wire          key_process_done_latch;
wire  [127:0] gift_cipher_out;
wire          gift_cipher_done;    

// gift_128_enc_instance
gift_128_enc INST_GIFT_128_ENC (
  .clk_i                  (clk_i                  ),
  .reset_n                (reset_n                ),
  .busy                   (                       ), // unused, may be used for another purpose
  .key_in                 (key_in                 ),
  .key_ld                 (key_ld                 ),
  .key_process_done_latch (key_process_done_latch ),
  .data_in                (data_in                ),
  .enc_start              (gift_data_ld           ),
  .cipher_out             (gift_cipher_out        ),
  .cipher_done            (gift_cipher_done       )
);


localparam IDLE               = 3'd0;
localparam WAIT_FOR_KEY_LOAD  = 3'd1;
localparam WAIT_FOR_DATA_LOAD = 3'd2;
localparam KEY_PROCESS_CHECK  = 3'd3;
localparam KEY_PROCEE_WAIT    = 3'd4;
localparam WAIT_FOR_ENC       = 3'd5;


reg [2:0]    state_reg         , state_nxt;
reg [127:0]  gift_key_in_reg   ,gift_key_in_nxt;
reg [127:0]  gift_data_in_reg  ,gift_data_in_nxt;
reg [127:0]  gift_data_out_reg ,gift_data_out_nxt;
reg          gift_key_ld       , gift_data_ld;
reg          gift_data_out_valid_reg, gift_data_out_valid_nxt; 
wire [127:0] key_in ;
wire [127:0] data_in;
wire         key_ld;



assign key_in    = gift_key_in_reg;
assign data_in   = gift_data_in_reg;
assign key_ld    = gift_key_ld;


always @(posedge clk_i, negedge reset_n) begin
  if (!reset_n) begin
    state_reg               <= IDLE;
    gift_data_in_reg        <= 'd0;
    gift_data_out_reg       <= 'd0;
    gift_key_in_reg         <= 'd0;
    gift_data_out_valid_reg <= 1'b0;
  end else begin
    state_reg               <= state_nxt;
    gift_data_in_reg        <= gift_data_in_nxt;
    gift_data_out_reg       <= gift_data_out_nxt;
    gift_key_in_reg         <= gift_key_in_nxt;
    gift_data_out_valid_reg <= gift_data_out_valid_nxt;
  end	  
end

always @* begin
  state_nxt               = state_reg;
  gift_key_ld             = 1'b0;
  gift_data_ld            = 1'b0;
  gift_data_out_valid_nxt = 1'b0;

  gift_key_in_nxt         = gift_key_in_reg;
  gift_data_in_nxt        = gift_data_in_reg;
  gift_data_out_nxt       = gift_data_out_reg;
  
  case(state_reg)
    IDLE: begin
      state_nxt       = WAIT_FOR_KEY_LOAD;
    end
    WAIT_FOR_KEY_LOAD: begin
      if (key_input_valid) begin
	gift_key_in_nxt = key_input;
	state_nxt       = WAIT_FOR_DATA_LOAD;
      end
    end
    WAIT_FOR_DATA_LOAD: begin
      if (data_input_valid) begin
        gift_data_in_nxt = data_input;
	state_nxt        = KEY_PROCESS_CHECK;
      end
    end
    KEY_PROCESS_CHECK: begin
      if (!key_process_done_latch) begin
        state_nxt   = KEY_PROCEE_WAIT;
	gift_key_ld = 1'b1;
      end else begin
        state_nxt    = WAIT_FOR_ENC;
	gift_data_ld = 1'b1;
      end
    end
    KEY_PROCEE_WAIT: begin
      if (key_process_done_latch) begin
        state_nxt    = WAIT_FOR_ENC;
	gift_data_ld = 1'b1;
      end	      
    end
    WAIT_FOR_ENC: begin
      if (gift_cipher_done) begin
        gift_data_out_nxt       = gift_cipher_out;
	gift_data_out_valid_nxt = 1'b1;
	state_nxt               = WAIT_FOR_KEY_LOAD;
      end 
    end
  endcase
end

assign cipher_out        = gift_data_out_reg;
assign cipher_out_valid  = gift_data_out_valid_reg;

endmodule

