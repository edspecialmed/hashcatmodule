/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

KERNEL_FQ void m04540_mxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }


  u32 s[4];
  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  s[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  s[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  

  const u32 combined_len = 36;

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0lr = w0l | w0r;
    w[0] = w0lr;

    // === STEP 1: SHA1(PASS) ===
    sha1_ctx_vector_t ctx1;
    sha1_init_vector (&ctx1);
    sha1_update_vector (&ctx1, w, pw_len);
    sha1_final_vector (&ctx1);

    
    u32x w_next[16]; 
    w_next[0] = s[0];
    w_next[1] = s[1];
    w_next[2] = s[2];
    w_next[3] = s[3];

  
    w_next[4] = hc_swap32 (ctx1.h[0]);
    w_next[5] = hc_swap32 (ctx1.h[1]);
    w_next[6] = hc_swap32 (ctx1.h[2]);
    w_next[7] = hc_swap32 (ctx1.h[3]);
    w_next[8] = hc_swap32 (ctx1.h[4]);
    
    
    //w_next[9] = 0; w_next[10] = 0; w_next[11] = 0; w_next[12] = 0;
    //w_next[13] = 0; w_next[14] = 0; w_next[15] = 0;

    // === STEP 2: SHA1(SALT . HASH1) ===
    sha1_ctx_vector_t ctx2;
    sha1_init_vector (&ctx2);
    
    sha1_update_vector (&ctx2, w_next, combined_len);
    sha1_final_vector (&ctx2);

    
    w_next[4] = hc_swap32 (ctx2.h[0]);
    w_next[5] = hc_swap32 (ctx2.h[1]);
    w_next[6] = hc_swap32 (ctx2.h[2]);
    w_next[7] = hc_swap32 (ctx2.h[3]);
    w_next[8] = hc_swap32 (ctx2.h[4]);

    // === STEP 3: SHA1(SALT . HASH2) ===
    sha1_ctx_vector_t ctxf;
    sha1_init_vector (&ctxf);
    sha1_update_vector (&ctxf, w_next, combined_len);
    sha1_final_vector (&ctxf);

    // === COMPARE ===
    
    const u32x r0 = hc_swap32 (ctxf.h[DGST_R0]);
    const u32x r1 = hc_swap32 (ctxf.h[DGST_R1]);
    const u32x r2 = hc_swap32 (ctxf.h[DGST_R2]);
    const u32x r3 = hc_swap32 (ctxf.h[DGST_R3]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m04540_sxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 s[4];
  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  s[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  s[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  
  const u32 combined_len = 36;

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0lr = w0l | w0r;
    w[0] = w0lr;

    sha1_ctx_vector_t ctx1;
    sha1_init_vector (&ctx1);
    sha1_update_vector (&ctx1, w, pw_len);
    sha1_final_vector (&ctx1);

    u32x w_next[16];
    w_next[0] = s[0];
    w_next[1] = s[1];
    w_next[2] = s[2];
    w_next[3] = s[3];

    w_next[4] = hc_swap32 (ctx1.h[0]);
    w_next[5] = hc_swap32 (ctx1.h[1]);
    w_next[6] = hc_swap32 (ctx1.h[2]);
    w_next[7] = hc_swap32 (ctx1.h[3]);
    w_next[8] = hc_swap32 (ctx1.h[4]);
    
    w_next[9] = 0; w_next[10] = 0; w_next[11] = 0; w_next[12] = 0;
    w_next[13] = 0; w_next[14] = 0; w_next[15] = 0;

    sha1_ctx_vector_t ctx2;
    sha1_init_vector (&ctx2);
    sha1_update_vector_64 (&ctx2, w_next, w_next + 4, w_next + 8, w_next + 12, combined_len);
    sha1_final_vector (&ctx2);

    w_next[4] = hc_swap32 (ctx2.h[0]);
    w_next[5] = hc_swap32 (ctx2.h[1]);
    w_next[6] = hc_swap32 (ctx2.h[2]);
    w_next[7] = hc_swap32 (ctx2.h[3]);
    w_next[8] = hc_swap32 (ctx2.h[4]);

    sha1_ctx_vector_t ctxf;
    sha1_init_vector (&ctxf);
    sha1_update_vector_64 (&ctxf, w_next, w_next + 4, w_next + 8, w_next + 12, combined_len);
    sha1_final_vector (&ctxf);

    const u32x r0 = hc_swap32 (ctxf.h[DGST_R0]);
    const u32x r1 = hc_swap32 (ctxf.h[DGST_R1]);
    const u32x r2 = hc_swap32 (ctxf.h[DGST_R2]);
    const u32x r3 = hc_swap32 (ctxf.h[DGST_R3]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
