using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Dynamic;

namespace SteamKit2
{
    /// <summary>
    /// Performs login using the API used by the Steam website.
    /// </summary>
    public static class WebLogin
    {
        public static string DoLogin(SteamID steamId, string loginKey)
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            return DoLogin(steamId, encoding.GetBytes(loginKey));
        }

        public static string DoLogin(SteamID steamId, byte[] loginKey)
        {
            using (dynamic userAuth = WebAPI.GetInterface("ISteamUserAuth")) {
                byte[] sessionKey = CryptoHelper.GenerateRandomBlock(32);
                byte[] encryptedKey = null;

                // TODO: handle other universes?
                byte[] universeKey = KeyDictionary.GetPublicKey( EUniverse.Public );
                using ( var rsa = new RSACrypto( universeKey ) )
                {
                    encryptedKey = rsa.Encrypt( sessionKey );
                }
                
                byte[] encryptedTicket = CryptoHelper.SymmetricEncrypt(loginKey, sessionKey);
                byte[] decryptedTicket = CryptoHelper.SymmetricDecrypt(encryptedTicket, sessionKey);
                KeyValue authResult = userAuth.AuthenticateUser(
                    steamid: steamId.ConvertToUInt64(),
                    sessionkey: WebHelpers.UrlEncode(encryptedKey),
                    encrypted_loginkey: WebHelpers.UrlEncode(encryptedTicket),
                    method: "POST"
                );

                return authResult["token"].AsString();
            }
        }
    }
}
