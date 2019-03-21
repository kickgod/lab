using LabExam.IServices;
using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace LabExam.Services
{
    public class EncryptionDataService:IEncryptionDataService
    {
        private const String EncodeKey = "sicnu_lab_505"; //无用
      
        string publicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoQh0wEqx/R2H1v00IU12Oc30fosRC/frhH89L6G+fzeaqI19MYQhEPMU13wpeqRONCUta+2iC1sgCNQ9qGGf19yGdZUfueaB1Nu9rdueQKXgVurGHJ+5N71UFm+OP1XcnFUCK4wT5d7ZIifXxuqLehP9Ts6sNjhVfa+yU+VjF5HoIe69OJEPo7OxRZcRTe17khc93Ic+PfyqswQJJlY/bgpcLJQnM+QuHmxNtF7/FpAx9YEQsShsGpVo7JaKgLo+s6AFoJ4QldQKir2vbN9vcKRbG3piElPilWDpjXQkOJZhUloh/jd7QrKFimZFldJ1r6Q59QYUyGKZARUe0KZpMQIDAQAB";
        
        string privateKey =
            "MIIEpAIBAAKCAQEAoQh0wEqx/R2H1v00IU12Oc30fosRC/frhH89L6G+fzeaqI19MYQhEPMU13wpeqRONCUta+2iC1sgCNQ9qGGf19yGdZUfueaB1Nu9rdueQKXgVurGHJ+5N71UFm+OP1XcnFUCK4wT5d7ZIifXxuqLehP9Ts6sNjhVfa+yU+VjF5HoIe69OJEPo7OxRZcRTe17khc93Ic+PfyqswQJJlY/bgpcLJQnM+QuHmxNtF7/FpAx9YEQsShsGpVo7JaKgLo+s6AFoJ4QldQKir2vbN9vcKRbG3piElPilWDpjXQkOJZhUloh/jd7QrKFimZFldJ1r6Q59QYUyGKZARUe0KZpMQIDAQABAoIBAQCRZLUlOUvjIVqYvhznRK1OG6p45s8JY1r+UnPIId2Bt46oSLeUkZvZVeCnfq9k0Bzb8AVGwVPhtPEDh73z3dEYcT/lwjLXAkyPB6gG5ZfI/vvC/k7JYV01+neFmktw2/FIJWjEMMF2dvLNZ/Pm4bX1Dz9SfD/45Hwr8wqrvRzvFZsj5qqOxv9RPAudOYwCwZskKp/GF+L+3Ycod1Wu98imzMZUH+L5dQuDGg3kvf3ljIAegTPoqYBg0imNPYY/EGoFKnbxlK5S5/5uAFb16dGJqAz3XQCz9Is/IWrOTu0etteqV2Ncs8uqPdjed+b0j8CMsr4U1xjwPQ8WwdaJtTkRAoGBANAndgiGZkCVcc9975/AYdgFp35W6D+hGQAZlL6DmnucUFdXbWa/x2rTSEXlkvgk9X/PxOptUYsLJkzysTgfDywZwuIXLm9B3oNmv3bVgPXsgDsvDfaHYCgz0nHK6NSrX2AeX3yO/dFuoZsuk+J+UyRigMqYj0wjmxUlqj183hinAoGBAMYMOBgF77OXRII7GAuEut/nBeh2sBrgyzR7FmJMs5kvRh6Ck8wp3ysgMvX4lxh1ep8iCw1R2cguqNATr1klOdsCTOE9RrhuvOp3JrYzuIAK6MpH/uBICy4w1rW2+gQySsHcH40r+tNaTFQ7dQ1tef//iy/IW8v8i0t+csztE1JnAoGABdtWYt8FOYP688+jUmdjWWSvVcq0NjYeMfaGTOX/DsNTL2HyXhW/Uq4nNnBDNmAz2CjMbZwt0y+5ICkj+2REVQVUinAEinTcAe5+LKXNPx4sbX3hcrJUbk0m+rSu4G0B/f5cyXBsi9wFCAzDdHgBduCepxSr04Sc9Hde1uQQi7kCgYB0U20HP0Vh+TG2RLuE2HtjVDD2L/CUeQEiXEHzjxXWnhvTg+MIAnggvpLwQwmMxkQ2ACr5sd/3YuCpB0bxV5o594nsqq9FWVYBaecFEjAGlWHSnqMoXWijwu/6X/VOTbP3VjH6G6ECT4GR4DKKpokIQrMgZ9DzaezvdOA9WesFdQKBgQCWfeOQTitRJ0NZACFUn3Fs3Rvgc9eN9YSWj4RtqkmGPMPvguWo+SKhlk3IbYjrRBc5WVOdoX8JXb2/+nAGhPCuUZckWVmZe5pMSr4EkNQdYeY8kOXGSjoTOUH34ZdKeS+e399BkBWIiXUejX/Srln0H4KoHnTWgxwNpTsBCgXu8Q==";



        /// <summary>
        ///  使用对称加密 密钥为上面
        /// </summary>
        /// <param name="Data">待加密数据</param>
        /// <returns>已经加密数据</returns>
        public string EncodeByRsa(string Data)
        {
            var rsa = new RSAHelper(RSAType.RSA2, Encoding.UTF8, privateKey, publicKey);
            string enStr = rsa.Encrypt(Data);
            return enStr;

            /* 它不支持跨平台
            CspParameters param = new CspParameters();
            param.KeyContainerName = EncodeKey;//密匙容器的名称，保持加密解密一致才能解密成功
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(param))
            {
                byte[] plaindata = Encoding.Default.GetBytes(Data);//将要加密的字符串转换为字节数组
                byte[] encryptdata = rsa.Encrypt(plaindata, false);//将加密后的字节数据转换为新的加密字节数组
                return Convert.ToBase64String(encryptdata);//将加密后的字节数组转换为字符串
            }
            */
        }

        /// <summary>
        /// 对RSA加密后的数据进行解密
        /// </summary>
        /// <param name="EncodedData">已经加密数据</param>
        /// <returns>原来的数据</returns>
        public string DecryptByRsa(string EncodedData)
        {

            var rsa = new RSAHelper(RSAType.RSA2, Encoding.UTF8, privateKey, publicKey);
            string deStr = rsa.Decrypt(EncodedData);
            return deStr;
            /* 它不支持跨平台
            CspParameters param = new CspParameters();
            param.KeyContainerName = EncodeKey;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(param))
            {
                byte[] encryptdata = Convert.FromBase64String(EncodedData);
                byte[] decryptdata = rsa.Decrypt(encryptdata, false);
                return Encoding.Default.GetString(decryptdata);
            }
            */
        }

        /// <summary>
        /// 返回私钥签名
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public String RsaSign(String str)
        {
            var rsa = new RSAHelper(RSAType.RSA2, Encoding.UTF8, privateKey, publicKey);
            return rsa.Sign(str);
        }

        /// <summary>
        /// 公钥验证签名
        /// </summary>
        /// <param name="str"></param>
        /// <param name="sStr"></param>
        /// <returns></returns>
        public Boolean RsaVerify(String str,String sStr)
        {
            var rsa = new RSAHelper(RSAType.RSA2, Encoding.UTF8, privateKey, publicKey);
            return rsa.Verify(str, sStr);
        }

        /// <summary>
        ///  <remarks> 通过MD5的方法对数据进行加密  </remarks>
        ///  <Create> 2018/9/6 19:55 </Create>
        ///  <Author> 2016110418 蒋星 </Author>
        ///  <LastAlterTimeAndAuthor>  </LastAlterTimeAndAuthor>
        /// </summary>
        public String EncodeByMd5(string Data)
        {
            if (String.IsNullOrEmpty(Data))
            {
                return "";
            }
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] palindata = Encoding.Default.GetBytes(Data);   //将要加密的字符串转换为字节数组
            byte[] encryptdata = md5.ComputeHash(palindata);      //将字符串加密后也转换为字符数组
            return Convert.ToBase64String(encryptdata);           //将加密后的字节数组转换为加密字符串
        }

        public string EncodeByMd5Times(string Data, int Time)
        {
            try
            {
                if (Time < 1)
                {
                    throw  new ArgumentException("整形参数不能小于1");
                }
                for (int i = 0; i < Time; i++)
                {
                    Data = EncodeByMd5(Data);
                }
                return Data;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
    }
}
