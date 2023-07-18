//************************************************************************//
// Author		: Inc                                             //
// Module Name		: gift_128_enc_tb.v                               //
// Date			: May 23                                          //
// Version		: v1                                              //
// Remarks		: Initial Draft                                   //
//                                                                        //
// ***********************************************************************//
`timescale 1 ns/ 1 ps

module gift_128_lp_tb;

reg                async_rst_n=1  ;
reg                clk_i = 0      ;

wire               busy            ;
reg [127:0]        key_in_enc  = 'd0   ;
reg [127:0]        key_in_dec  = 'd0   ;
reg [127:0]        data_in = 'd0   ;
reg                data_in_valid= 1'b0 ;

wire [127:0]       cipher_out      ;
wire               cipher_out_valid     ;

reg                dec_start = 1'b0;
wire [127:0]       plain_out       ;
wire               dec_done        ;
reg                key_ld_dec = 1'b0   ;
wire               key_process_done_latch_dec;
wire               key_process_done_latch_enc;
reg  [127:0]       key_in = 'd0;
reg                key_ld_enc = 'd0;


integer t = 0;
integer NO_OF_TEST_CASES = 100;
integer NO_PASS          = 0;
integer NO_FAIL          = 0;

task async_reset_generator; begin
    async_rst_n = 1'b1;
    #100;
    async_rst_n = 1'b0;
    #100;
    async_rst_n = 1'b1;
  end
endtask    

// clock generator
always #10 clk_i = ~clk_i;

task load_enc_key(input [127:0] key_data); begin
  $display ("------------------------------------");	
  $display ("Keyloading of encryption has started");	
  $display ("------------------------------------");	
  #20;
  @(negedge clk_i);
  key_ld_enc    = 1'b1; 
  key_in_enc    = key_data;
  @(negedge clk_i);
  key_ld_enc    = 1'b0;
  #10;
  //wait (key_process_done_latch_enc);
  $display ("--------------------------------------");	
  $display ("Key loading of encryption was done....");
  $display ("--------------------------------------");	
end
endtask

task do_enc (input [127:0] plain_data); begin
  $display ("--------------------------------------");	
  $display (" Encryption Process has started....   ");
  $display ("--------------------------------------");	
  @(negedge clk_i);
  data_in_valid  = 1'b1;
  data_in        = plain_data; 
  @(negedge clk_i);
  data_in_valid = 1'b0;

  wait (cipher_out_valid);
  $display ("--------------------------------------");	
  $display ("Encryption is completed..."); 
  $display ("cipher : %h",cipher_out);
  $display ("--------------------------------------");	
end
endtask

task do_dec (input [127:0] expected_data); begin
  $display ("--------------------------------------");	
  $display (" Decryption Process has started....   ");
  $display ("--------------------------------------");	
  @(negedge clk_i);
  dec_start = 1'b1; 
  @(negedge clk_i);
  dec_start = 1'b0;
  wait (dec_done);
  $display ("--------------------------------------");	
  $display ("Deccryption is completed..."); 
  $display ("Plain : %h",plain_out);
  if (plain_out == expected_data) begin
    $display ("+++++++++++++++++++++++++++++++++++++++");	  
    $display (" Success : Matching Data               ");
    $display ("+++++++++++++++++++++++++++++++++++++++");
    NO_PASS = NO_PASS + 1;    
  end
  else begin
    $display ("######################################");	  
    $display ("Fail : Mis Matching Data              ");
    $display ("######################################");
    NO_FAIL = NO_FAIL + 1;
    $finish;                                              // Terminate the process on error generation    
  end
  $display ("--------------------------------------");	
end
endtask

task load_dec_key(input [127:0] key_data); begin
  $display ("------------------------------------");	
  $display ("Keyloading of deccryption has started");	
  $display ("------------------------------------");	
  #20;
  @(negedge clk_i);
  key_ld_dec    = 1'b1; 
  key_in_dec    = key_in;
  @(negedge clk_i);
  key_ld_dec    = 1'b0;
  #10;
  wait (key_process_done_latch_dec);
  $display ("----------------------------------------");	
  $display ("Key processing of decryption was done...");
  $display ("----------------------------------------");	
end
endtask

initial begin
  $dumpfile ("gift_128_lp_tb.vcd");
  $dumpvars (0, gift_128_lp_tb);    
  #100;
  async_reset_generator;
  #100;

  wait (async_rst_n == 1'b1);
  $display ("::::::::::::::: ASYN RESET IS HIGH ::::::::::");

  //------------------------------------------------------------------
  // Top level Symmetric Key
  //------------------------------------------------------------------
  //key_in  = 128'd0;
  //data_in = 128'd0;
  
  key_in  = 128'h01_23_45_67_89_ab_cd_ef_01_23_45_67_89_ab_cd_ef;
  data_in = 128'h01_23_45_67_89_ab_cd_ef_01_23_45_67_89_ab_cd_ef;

  //--------------------------------------------------------------------
  // Load key of Encryption 
  //--------------------------------------------------------------------
  //load_enc_key (key_in);
  //--------------------------------------------------------------------
  // Load key of decryption 
  //--------------------------------------------------------------------
  //load_dec_key (key_in);

  for (t=0;t < NO_OF_TEST_CASES;t=t+1) begin
    data_in = data_in + t;
    //key_in  = key_in + t;	  
    $display  ("-----------------------------------------------------"); 
    $display ("Plain data: %h",data_in);
    $display ("Key   data: %h",key_in );
    $display  ("-----------------------------------------------------"); 
    load_enc_key (key_in);
    //--------------------------------------------------------------------
    // Strat the Encryption 
    //--------------------------------------------------------------------
    do_enc (data_in);
    //--------------------------------------------------------------------

    load_dec_key (key_in);
    //--------------------------------------------------------------------
    // Strat the Decryption 
    //--------------------------------------------------------------------
    do_dec (data_in);
    //--------------------------------------------------------------------
    #100;
  end
  
  $display ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
  $display ("                     SUMMARY                                 "); 
  $display ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
  $display ("No of Test Cases : %d",NO_OF_TEST_CASES);
  $display ("No of PASS       : %d", NO_PASS);
  $display ("No of FAIL       : %d", NO_FAIL);
  $display ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

  #100;

  $finish;    
end


//gift_128_enc GIFT_128_ENC_U1(
//  .clk_i                   (clk_i                     ),
//  .reset_n                 (async_rst_n               ),
//  .busy                    (busy                      ),
//  .key_in                  (key_in_enc                ),
//  .key_ld                  (key_ld_enc                ),
//  .key_process_done_latch  (key_process_done_latch_enc),
//  .data_in                 (data_in                   ),
//  .enc_start               (enc_start                 ),
//  .cipher_out              (cipher_out                ),
//  .cipher_done             (cipher_done               )
//);

gift_enc_core_controller INST_GIFT_CORE_CONTROLLER (
  .clk_i            (clk_i           ),
  .reset_n          (async_rst_n     ),
  .key_input_valid  (key_ld_enc      ),
  .key_input        (key_in_enc      ),
  .data_input_valid (data_in_valid   ),
  .data_input       (data_in         ),
  .cipher_out_valid (cipher_out_valid),
  .cipher_out       (cipher_out      )
);




gift_128_dec GIFT_128_DEC_U1(
  .clk_i                   (clk_i                     ),
  .reset_n                 (async_rst_n               ),
  .busy                    (busy                      ),
  .key_in                  (key_in_dec                ),
  .key_ld                  (key_ld_dec                ),
  .key_process_done_latch  (key_process_done_latch_dec),
  .cipher_in               (cipher_out                ),
  .dec_start               (dec_start                 ),
  .plain_out               (plain_out                 ),
  .dec_done                (dec_done                  )
);


endmodule 
