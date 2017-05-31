

-- STORE PROCEDURE MA HOA LUONG CUA NHAN VIEN BANG THUAT TOAN AES 256, VOI KHOA LA MAT KHAU TAI KHOAN NHAN VIEN

CREATE OR REPLACE PROCEDURE SP_ENCRYPT_LUONG_AES256 (p_MANV IN VARCHAR2, p_key IN VARCHAR2)
AS
   p_input            VARCHAR2(200);
   output_string      VARCHAR2(200);
   encrypted_raw      RAW(2000);
   encryption_type    PLS_INTEGER;
   key_pass           RAW(32);
   key_temp           VARCHAR2(32);
BEGIN  
    encryption_type := DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5;    
    
    SELECT LUONG INTO p_input FROM NHAN_VIEN WHERE MANV = p_MANV;
    key_temp := DBMS_OBFUSCATION_TOOLKIT.md5 (input => UTL_RAW.cast_to_raw(p_key));
    key_pass := UTL_I18N.STRING_TO_RAW (key_temp, 'AL32UTF8');
    
    encrypted_raw := DBMS_CRYPTO.ENCRYPT
      (
         src => UTL_I18N.STRING_TO_RAW (p_input, 'AL32UTF8'),
         typ => encryption_type,
         key => key_pass
      );
    
    UPDATE NHAN_VIEN
    SET LUONG = encrypted_raw
    WHERE MANV = p_MANV;
END;


-- STORE PROCEDURE GIAI MA LUONG CUA NHAN VIEN, VOI KHOA LA MAT KHAU TAI KHOAN NHAN VIEN

CREATE OR REPLACE PROCEDURE SP_DECRYPT_LUONG_AES256 (p_MANV IN VARCHAR2, p_key IN VARCHAR2, p_LUONG OUT VARCHAR2)
AS
  p_input            VARCHAR2(200);
  key_pass           RAW(32);
  key_temp           VARCHAR2(32);
  encryption_type    PLS_INTEGER;
  encrypted_raw      RAW(2000);
  decrypted_raw      RAW(2000);
BEGIN
  SELECT LUONG INTO p_input FROM NHAN_VIEN WHERE MANV = p_MANV;
  encryption_type := DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5;
  encrypted_raw := UTL_I18N.STRING_TO_RAW(p_input, 'AL32UTF8');
    
  key_temp := DBMS_OBFUSCATION_TOOLKIT.md5 (input => UTL_RAW.cast_to_raw(p_key));
  key_pass := UTL_I18N.STRING_TO_RAW (key_temp, 'AL32UTF8'); 
  
  decrypted_raw := DBMS_CRYPTO.DECRYPT
      (
         src => p_input,
         typ => encryption_type,
         key => key_pass
      );
  
  p_LUONG := UTL_I18N.RAW_TO_CHAR (decrypted_raw, 'AL32UTF8');
END;




