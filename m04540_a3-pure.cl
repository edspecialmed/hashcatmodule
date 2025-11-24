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


DECLSPEC void m04540_process (const u32 *w, const u32 pw_len, const u32x *s, const u32 salt_len, u32x *r)
{
  // === STEP 1: H1 = SHA1(Pass) ===
  sha1_ctx_vector_t ctx1;
  sha1_init_vector (&ctx1);
  sha1_update_vector (&ctx1, w, pw_len);
  sha1_final_vector (&ctx1);

 
  u32x w_hash[16];
  w_hash[0] = hc_swap32 (ctx1.h[0]);
  w_hash[1] = hc_swap32 (ctx1.h[1]);
  w_hash[2] = hc_swap32 (ctx1.h[2]);
  w_hash[3] = hc_swap32 (ctx1.h[3]);
  w_hash[4] = hc_swap32 (ctx1.h[4]);

  // === STEP 2: H2 = SHA1(Salt . H1) ===
  sha1_ctx_vector_t ctx2;
  sha1_init_vector (&ctx2);
  
  // pinguin advice
  sha1_update_vector (&ctx2, s, salt_len);
  sha1_update_vector (&ctx2, w_hash, 20); 
  
  sha1_final_vector (&ctx2);

  
  w_hash[0] = hc_swap32 (ctx2.h[0]);
  w_hash[1] = hc_swap32 (ctx2.h[1]);
  w_hash[2] = hc_swap32 (ctx2.h[2]);
  w_hash[3] = hc_swap32 (ctx2.h[3]);
  w_hash[4] = hc_swap32 (ctx2.h[4]);

  // === STEP 3: H3 = SHA1(Salt . H2) ===
  sha1_ctx_vector_t ctxf;
  sha1_init_vector (&ctxf);

  // 2 updates
  sha1_update_vector (&ctxf, s, salt_len);
  sha1_update_vector (&ctxf, w_hash, 20);
  
  sha1_final_vector (&ctxf);

  
  r[0] = ctxf.h[0];
  r[1] = ctxf.h[1];
  r[2] = ctxf.h[2];
  r[3] = ctxf.h[3];
}

KERNEL_FQ void m04540_mxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };
  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1) {
    w[idx] = pws[gid].i[idx];
  }

  
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;
  u32x s[64] = { 0 };
  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx]; 
  }

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    w[0] = w0l | w0r;

    u32x r[4];
    m04540_process (w, pw_len, s, salt_len, r);

    COMPARE_M_SIMD (r[0], r[1], r[2], r[3]);
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
  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1) {
    w[idx] = pws[gid].i[idx];
  }

  
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;
  u32x s[64] = { 0 };
  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx]; 
  }

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    w[0] = w0l | w0r;

    u32x r[4];
    m04540_process (w, pw_len, s, salt_len, r);

    COMPARE_S_SIMD (r[0], r[1], r[2], r[3]);
  }
}
