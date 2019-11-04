from binascii import unhexlify
from copy import copy
import json
from pathlib import Path

import pytest

from jsf import JSF, InvalidJWSSignature, JWK, base64url_encode


p256privatekey = JWK(**{
    "kid": "example.com:p256",
    "kty": "EC",
    "crv": "P-256",
    "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
    "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY",
    "d": "nEsftLbi5u9pI8B0-drEjIuJzQgZie3yeqUR3BwWDl4"
})


p256_es256_jwk = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES256",
        "publicKey": {
            "kty": "EC",
            "crv": "P-256",
            "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
            "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY"
        },
        "value": "DaLAAenX3yOC7ycVyfjIe3tLyrH0U04lPcnQ7ct72ixryZVHdAWQazgDlWhpIDnrgLC0Pq03AvgsCc4ROOCInQ"
    }
}


p256_es256_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES256",
        "keyId": "example.com:p256",
        "value": "LOQWD_W6fdaGnolsKHztGco78WHfsZ9cNiJkGoYMCWkBQSPh5D8OmV_XkNnKM6Yu2WvMgovHvs_oxmnNaazPng"
    }
}


p256_es256_imp = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES256",
        "value": "dfkNQOOsCCEU_EX78U2p3Qm9bkwpKJxlTPwdQ8Yovry1WxhhfKWYmkzUaFDqkeYffqfm3_ltwrDkdpbjxYkbnA"
    }
}


p256_es256_cer = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES256",
        "certificatePath": [
            #...,...8...,..16...,..24...,..32...,..40...,..48...,..56...,..64
            "MIIB-TCCAVigAwIBAgIGAWFcc4YkMAwGCCqGSM49BAMEBQAwLTELMAkGA1UEBhMC"
            "RVUxHjAcBgNVBAMTFVRydXN0IE5ldHdvcmsgU3ViIENBMzAeFw0xODAxMDEwMDAw"
            "MDBaFw0yMjEyMzEyMzU5NTlaMDIxCzAJBgNVBAYTAkZSMQ0wCwYDVQQFEwQ0NTAx"
            "MRQwEgYDVQQDEwtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA"
            "BHHp7A83DBJIInj8-g1we3A7sBXprIQBUfdFDVUBQoPExq8rze6ewG0-eVcSF72J"
            "77gKiD0IHnzpwHaU7t6nVeajXTBbMAkGA1UdEwQCMAAwDgYDVR0PAQH_BAQDAgP4"
            "MB0GA1UdDgQWBBQQyJ9rXSIskoUuA946von62LoxqzAfBgNVHSMEGDAWgBTUWrS5"
            "4qC2NgG3UK6rVAr0gbQ0MTAMBggqhkjOPQQDBAUAA4GMADCBiAJCAaWoVQ0r6jFj"
            "hO5e0WJTgyMmA8BhpO1t7gXQ6xoKGso9jCOYf9OG9BFfZoVmdIyfYiwkhy1ld27t"
            "iOJ5X4m6WasRAkIBpEkUDf8irbSZ1V7zXALaR2mJTjKQV_5jRHsiBQWA-5DxEa-x"
            "_zJVRz8tpp-jjT2tSCU82bwUOBLu6te1YIDpWCA",
            "MIIDsTCCAZmgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAuMQswCQYDVQQGEwJVUzEf"
            "MB0GA1UEAxMWVHJ1c3QgTmV0d29yayBSb290IENBMTAeFw0xNjA3MTAxMDAwMDBa"
            "Fw0yNTA3MTAwOTU5NTlaMC0xCzAJBgNVBAYTAkVVMR4wHAYDVQQDExVUcnVzdCBO"
            "ZXR3b3JrIFN1YiBDQTMwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGJzPZsjniw"
            "yZeXrgrlQM3Y13r3znR8FSQpKbC2bplrOWySQJPGm-GFObe5Dk4t3Jrtk_Pbs8-3"
            "VW_4q5drL0YqYwBYNJPhqjbSM6SGHrc6wNdPZRw_WnJVa0ELXKICC73lkjskWPfE"
            "-cLpZ3sTq1ovEmoNjgaySVRUH1wFDdkqyReJaKNjMGEwDwYDVR0TAQH_BAUwAwEB"
            "_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNRatLnioLY2AbdQrqtUCvSBtDQx"
            "MB8GA1UdIwQYMBaAFEkmC1HDAh0fXehpiUhUGE868Hk2MA0GCSqGSIb3DQEBDQUA"
            "A4ICAQAs2KADYyGQCVy8tJZWakNtGdww4OumZpBuR66p_2xK7veRubQEhG-nJn7o"
            "VkJ4w5pEec3sYQEqtPbHyZcEKEYbOJ2cVf1nMH-DvFZ6ypQocGRp3WSWsTzL3Sgq"
            "iWrQdPX1Y5dO6Hvx7p9ST9H2WgkxB-Q75Jov1gVF3bScAbxb7Mw7tf5z3Cvqmfo0"
            "Gatkgzz6-jDPrtUK7AAAOw3C0kHMbE3EnNarsfhBkUerE8QVmHIvz373mWt0Sngu"
            "aHq0A9ZuSia_pF7bgfVRZi2ZzIzpu2O276sB2Yji9tcSn5l21jq63rXtvY_DLAi4"
            "kaLyf9sHT_tkH-gkTdkdkfQq8sA5ysRW21wPQbmjTIVwsfY4JjajVIUitjPbkUJq"
            "URpf2VD0JXdYQHS6KVPWqHWTlKPlsKbhw4ghuLqCMYda88L9rxWnSC5L8s0DJSuB"
            "Bm-nq23NtHl5FbCzeXWcKRayIgimT-An1WIOeJP4F7-BctYLIooKoQzJZR1tOWvp"
            "rUs22_xAivVBz7J_LmJyVlKesB2ic8qYdt7YVoCsWrnEUgoNoJPwLHeva8KPvd0g"
            "LXrwaMyTCCjeoemXFj6nCbbMHJeVffh6jYBAzlbcAEvTiZcdzrVVr54kOtWskyae"
            "DnAcMXW4Of1vWdUJ2as5nyfletfTp4E6A9P2dZ5g7nMoL90yIw"
        ],
        "value": "OyltWriKjFuc2QLty_FvgEutNZcRHhNPDhi_lSBCn_zI-8pYhlwsY7cR4DcxlBFJ1rTr1L1tC1YaG59Hyt2tWQ"
    }
}


p256_es256_name = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "authorizationSignature": {
        "algorithm": "ES256",
        "publicKey": {
            "kty": "EC",
            "crv": "P-256",
            "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
            "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY"
        },
        "value": "_5X5hahBoA_HsbvbXstKKvDKMl-b36GZa0rNBw9oZqC2sk5FdkWrpywy8X55cTXeIRNcFd1LxDPdDDHUQqwmVA"
    }
}


p256_es256_exts = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES256",
        "publicKey": {
            "kty": "EC",
            "crv": "P-256",
            "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
            "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY"
        },
        "extensions": ["otherExt", "https://example.com/extension"],
        "otherExt": "Cool Stuff",
        "https://example.com/extension": {
            "life-is-great": True
        },
        "value": "THxzfI5M3V-ZofagQcW97YuQBEIUZpo28p2Gq4xxSw4EesqTAkKqPgVKJAjceZSsWgYu6KMgdxH26T2bcgtkBQ"
    }
}


p256_es256_excl = {
    "mySignedData": "something",
    "myUnsignedData": "something else",
    "signature": {
        "algorithm": "ES256",
        "publicKey": {
            "kty": "EC",
            "crv": "P-256",
            "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
            "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY"
        },
        "excludes": ["myUnsignedData"],
        "value": "18HYl2jLzfVNhmTFPcK4eycWU-0_bSpCKYXXDztwFUt5asXboZCe61jelMU8l1u4EUoUXVXXBE4_qMkmj7Zafw"
    }
}


p384privatekey = JWK(**{
    "kid": "example.com:p384",
    "kty": "EC",
    "crv": "P-384",
    "x": "GLfdsvEwphRzS_twup7UFPVOk7_CKgHZ7dt_fJ2QHPBdJa1c5pfJcRIWTfT0lpg9",
    "y": "ovA5_QXmFbj9U4pjZ1AX_ZdVyIRZUBWW9cuZda_tupKfWQfmcQHzDmHGHbxl9Xxl",
    "d": "Qsgq80kMs40sAn1gB7gLxAk1se37Kmh9AG18wWZ3SqgcPPRq1wwidNTi866Gt4_0"
})


p384_es384_jwk = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES384",
        "publicKey": {
            "kty": "EC",
            "crv": "P-384",
            "x": "GLfdsvEwphRzS_twup7UFPVOk7_CKgHZ7dt_fJ2QHPBdJa1c5pfJcRIWTfT0lpg9",
            "y": "ovA5_QXmFbj9U4pjZ1AX_ZdVyIRZUBWW9cuZda_tupKfWQfmcQHzDmHGHbxl9Xxl"
        },
        "value": "2NwqrIoF841LlI6A-aWme0ig0TfEVCkGwIVbfp_I_3nUi6ez307B508JE61viwMc"
                 "PUYaFHz8YeZ1M1krUYH-qmscfXHUN3OTimgTxGKUk7dsv_WLfi5TdccvkMP6Nuvf"
    }
}


p384_es384_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES384",
        "keyId": "example.com:p384",
        "value": "OdEQM8N1m36PbTEOLs0Q3m-pBDyKLKDD1WMr76DsOqJ-0IjeVBPhK4TuacCxRl1u"
                 "Ov8egRrUWhZf5lenOKZ-NMZDcNtqAIs2j40Vl85wqjBI-GFcbtU3UOcz4vQeeZ9L"
    }
}


p384_es384_imp = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES384",
        "value": "rIZo67puCjHUAygCvrPLPAmj__6XsDCnxItzwAPJKcPwNHK8sPscFivVga7ie0Cl"
                 "RRoQNp5sBlJk6wpAjL95td8dCe4WnVV5sBOTyc4_WIjUnxGRgoEtdW_KnvFGWRB7"
    }
}


p384_es384_cer = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES384",
        "certificatePath": [
            "MIICFjCCAXWgAwIBAgIGAWFcc4yUMAwGCCqGSM49BAMEBQAwLTELMAkGA1UEBhMC"
            "RVUxHjAcBgNVBAMTFVRydXN0IE5ldHdvcmsgU3ViIENBMzAeFw0xODAxMDEwMDAw"
            "MDBaFw0yMjEyMzEyMzU5NTlaMDIxCzAJBgNVBAYTAkZSMQ0wCwYDVQQFEwQ0NTAx"
            "MRQwEgYDVQQDEwtleGFtcGxlLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABBi3"
            "3bLxMKYUc0v7cLqe1BT1TpO_wioB2e3bf3ydkBzwXSWtXOaXyXESFk309JaYPaLw"
            "Of0F5hW4_VOKY2dQF_2XVciEWVAVlvXLmXWv7bqSn1kH5nEB8w5hxh28ZfV8ZaNd"
            "MFswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCA_gwHQYDVR0OBBYEFG9foq5m0pyZ"
            "G7r3G23hxzYTkFZ1MB8GA1UdIwQYMBaAFNRatLnioLY2AbdQrqtUCvSBtDQxMAwG"
            "CCqGSM49BAMEBQADgYwAMIGIAkIBtNCYJ9-XaOGtdIEbxYUcqQZRtiX54Ltx7YGW"
            "tk1bK51m6plv8_AspvX1mhA8nZ__hmoKChMLccZIicMXBmJV26oCQgDO34bxnJ1M"
            "VBTNbhBkHfEiJAJZNtW2tXdEnduJpfYMb4lWJNssCVBS8YtyKEQRuGT8uKN7inbi"
            "6L_8FQTtJ9yLhg",
            "MIIDsTCCAZmgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAuMQswCQYDVQQGEwJVUzEf"
            "MB0GA1UEAxMWVHJ1c3QgTmV0d29yayBSb290IENBMTAeFw0xNjA3MTAxMDAwMDBa"
            "Fw0yNTA3MTAwOTU5NTlaMC0xCzAJBgNVBAYTAkVVMR4wHAYDVQQDExVUcnVzdCBO"
            "ZXR3b3JrIFN1YiBDQTMwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGJzPZsjniw"
            "yZeXrgrlQM3Y13r3znR8FSQpKbC2bplrOWySQJPGm-GFObe5Dk4t3Jrtk_Pbs8-3"
            "VW_4q5drL0YqYwBYNJPhqjbSM6SGHrc6wNdPZRw_WnJVa0ELXKICC73lkjskWPfE"
            "-cLpZ3sTq1ovEmoNjgaySVRUH1wFDdkqyReJaKNjMGEwDwYDVR0TAQH_BAUwAwEB"
            "_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNRatLnioLY2AbdQrqtUCvSBtDQx"
            "MB8GA1UdIwQYMBaAFEkmC1HDAh0fXehpiUhUGE868Hk2MA0GCSqGSIb3DQEBDQUA"
            "A4ICAQAs2KADYyGQCVy8tJZWakNtGdww4OumZpBuR66p_2xK7veRubQEhG-nJn7o"
            "VkJ4w5pEec3sYQEqtPbHyZcEKEYbOJ2cVf1nMH-DvFZ6ypQocGRp3WSWsTzL3Sgq"
            "iWrQdPX1Y5dO6Hvx7p9ST9H2WgkxB-Q75Jov1gVF3bScAbxb7Mw7tf5z3Cvqmfo0"
            "Gatkgzz6-jDPrtUK7AAAOw3C0kHMbE3EnNarsfhBkUerE8QVmHIvz373mWt0Sngu"
            "aHq0A9ZuSia_pF7bgfVRZi2ZzIzpu2O276sB2Yji9tcSn5l21jq63rXtvY_DLAi4"
            "kaLyf9sHT_tkH-gkTdkdkfQq8sA5ysRW21wPQbmjTIVwsfY4JjajVIUitjPbkUJq"
            "URpf2VD0JXdYQHS6KVPWqHWTlKPlsKbhw4ghuLqCMYda88L9rxWnSC5L8s0DJSuB"
            "Bm-nq23NtHl5FbCzeXWcKRayIgimT-An1WIOeJP4F7-BctYLIooKoQzJZR1tOWvp"
            "rUs22_xAivVBz7J_LmJyVlKesB2ic8qYdt7YVoCsWrnEUgoNoJPwLHeva8KPvd0g"
            "LXrwaMyTCCjeoemXFj6nCbbMHJeVffh6jYBAzlbcAEvTiZcdzrVVr54kOtWskyae"
            "DnAcMXW4Of1vWdUJ2as5nyfletfTp4E6A9P2dZ5g7nMoL90yIw"
        ],
        "value": "oHdu5BWvOVRWkce145PEXJzoBq6h9uwmUdULD7IZBDjdxMgAzEvIH0a-rQZxJBHx"
                 "joo8bQGK_AZEMUXKWkAUUVh0eA42p8I2uE3d9ggz84wk5zqK9bL6zXvs40dFiYn2"
    }
}


p521privatekey = JWK(**{
    "kid": "example.com:p521",
    "kty": "EC",
    "crv": "P-521",
    "x": "AT9Hw32aVQCGd5csltC1dqhSB4fFt-mEWO-QxZqrr9Yrwn69_q7n1YOYrHSWjk_qMkCGk6qQ4f9ZRYIJPGqjfxC9",
    "y": "AeVHV1elHFzR_P5Lzb22hMyhAzcGSTT1sdwVmFkJGBYt55RKXGNO1H9De2v_p5S-kkK8BZVh3JGzixMyT0Eo_ckS",
    "d": "AYSlWWbGUougMnE2r7pRkiHZfXBgUzaVTuWfE0X7PDYodsVXVzRiz4KMgfs5Xowwk2roUsbJV7wdyZ83qMrQM1Fv"
})


p521_es512_jwk = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES512",
        "publicKey": {
            "kty": "EC",
            "crv": "P-521",
            "x": "AT9Hw32aVQCGd5csltC1dqhSB4fFt-mEWO-QxZqrr9Yrwn69_q7n1YOYrHSWjk_qMkCGk6qQ4f9ZRYIJPGqjfxC9",
            "y": "AeVHV1elHFzR_P5Lzb22hMyhAzcGSTT1sdwVmFkJGBYt55RKXGNO1H9De2v_p5S-kkK8BZVh3JGzixMyT0Eo_ckS"
        },
        "value": "AJ659xkbRdTlQQQpcV0dSbZ9DvtpIPTP2l00Xsrbp3PrXPzmJtGzDTnL4hz813Sz"
                 "Lgq7ZJZ5ZR7fGvMQ6E_XO-2MAPrGAe5Kny4M2IPbeYuSTRXNvGhshNmhrSveTSqc"
                 "AOZ3NLd-7KL55KKvF81eAkSxyRF1uyiPy2qK9bozrpz3oWem"
    }
}


p521_es512_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES512",
        "keyId": "example.com:p521",
        "value": "AUK-81LqhaknISR5uMF6pObvaniK3DOlcIovfa8neZ6scO504OkWvBwjpPj89iVy"
                 "DcfoEpYxHK0ejHc42mK5Vmj1AdiZUt5Z7W_d973g3SHqR4o_pufkBMHPL2sSccXU"
                 "vk7nBpKsOHS1ZacMU6Z_prRRGd4-2tpBpHcbyTqPgmSsAlZD"
    }
}


p521_es512_imp = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES512",
        "value": "AX8iryVyPAGmbo58p5a-7MkyeOEnOgYFHWl2H0TFC4tIEWsYdea4XkksTt0aEFGx"
                 "-k0XgNcmgAiDgE1B1jbANuu8AVGXqUqnXiTGDLUMr_t7_lMGf2rxO6ADOQntAuh0"
                 "AuOuCmfM_DAhVxDOM4HrCUA6VLXK0kSiW9b4lTxwIC7Opj9B"
    }
}


p521_es512_cer = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "ES512",
        "certificatePath": [
            "MIICOzCCAZugAwIBAgIGAWFcc5MjMAwGCCqGSM49BAMEBQAwLTELMAkGA1UEBhMC"
            "RVUxHjAcBgNVBAMTFVRydXN0IE5ldHdvcmsgU3ViIENBMzAeFw0xODAxMDEwMDAw"
            "MDBaFw0yMjEyMzEyMzU5NTlaMDIxCzAJBgNVBAYTAkZSMQ0wCwYDVQQFEwQ0NTAx"
            "MRQwEgYDVQQDEwtleGFtcGxlLmNvbTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE"
            "AT9Hw32aVQCGd5csltC1dqhSB4fFt-mEWO-QxZqrr9Yrwn69_q7n1YOYrHSWjk_q"
            "MkCGk6qQ4f9ZRYIJPGqjfxC9AeVHV1elHFzR_P5Lzb22hMyhAzcGSTT1sdwVmFkJ"
            "GBYt55RKXGNO1H9De2v_p5S-kkK8BZVh3JGzixMyT0Eo_ckSo10wWzAJBgNVHRME"
            "AjAAMA4GA1UdDwEB_wQEAwID-DAdBgNVHQ4EFgQUa-tPMR1eN_0bbadpgzj-C5t-"
            "fMswHwYDVR0jBBgwFoAU1Fq0ueKgtjYBt1Cuq1QK9IG0NDEwDAYIKoZIzj0EAwQF"
            "AAOBiwAwgYcCQgFNJcVPfnQh7VeKnsXp1ay6oX9WSDN6RtTDAQ-4LZlIj8quUsKN"
            "7JH78fcqJgB3no8s6-N6vkyNTdAUQuhnuqeS0AJBEIF9NuLOuIaQW7ZPR1x95Owo"
            "rMGyXq0vKonMnijD5utltRmhZLdwI-GVX5k0V2-cGoTBKp3K2uFHPsTFVGSFRlU",
            "MIIDsTCCAZmgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAuMQswCQYDVQQGEwJVUzEf"
            "MB0GA1UEAxMWVHJ1c3QgTmV0d29yayBSb290IENBMTAeFw0xNjA3MTAxMDAwMDBa"
            "Fw0yNTA3MTAwOTU5NTlaMC0xCzAJBgNVBAYTAkVVMR4wHAYDVQQDExVUcnVzdCBO"
            "ZXR3b3JrIFN1YiBDQTMwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGJzPZsjniw"
            "yZeXrgrlQM3Y13r3znR8FSQpKbC2bplrOWySQJPGm-GFObe5Dk4t3Jrtk_Pbs8-3"
            "VW_4q5drL0YqYwBYNJPhqjbSM6SGHrc6wNdPZRw_WnJVa0ELXKICC73lkjskWPfE"
            "-cLpZ3sTq1ovEmoNjgaySVRUH1wFDdkqyReJaKNjMGEwDwYDVR0TAQH_BAUwAwEB"
            "_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNRatLnioLY2AbdQrqtUCvSBtDQx"
            "MB8GA1UdIwQYMBaAFEkmC1HDAh0fXehpiUhUGE868Hk2MA0GCSqGSIb3DQEBDQUA"
            "A4ICAQAs2KADYyGQCVy8tJZWakNtGdww4OumZpBuR66p_2xK7veRubQEhG-nJn7o"
            "VkJ4w5pEec3sYQEqtPbHyZcEKEYbOJ2cVf1nMH-DvFZ6ypQocGRp3WSWsTzL3Sgq"
            "iWrQdPX1Y5dO6Hvx7p9ST9H2WgkxB-Q75Jov1gVF3bScAbxb7Mw7tf5z3Cvqmfo0"
            "Gatkgzz6-jDPrtUK7AAAOw3C0kHMbE3EnNarsfhBkUerE8QVmHIvz373mWt0Sngu"
            "aHq0A9ZuSia_pF7bgfVRZi2ZzIzpu2O276sB2Yji9tcSn5l21jq63rXtvY_DLAi4"
            "kaLyf9sHT_tkH-gkTdkdkfQq8sA5ysRW21wPQbmjTIVwsfY4JjajVIUitjPbkUJq"
            "URpf2VD0JXdYQHS6KVPWqHWTlKPlsKbhw4ghuLqCMYda88L9rxWnSC5L8s0DJSuB"
            "Bm-nq23NtHl5FbCzeXWcKRayIgimT-An1WIOeJP4F7-BctYLIooKoQzJZR1tOWvp"
            "rUs22_xAivVBz7J_LmJyVlKesB2ic8qYdt7YVoCsWrnEUgoNoJPwLHeva8KPvd0g"
            "LXrwaMyTCCjeoemXFj6nCbbMHJeVffh6jYBAzlbcAEvTiZcdzrVVr54kOtWskyae"
            "DnAcMXW4Of1vWdUJ2as5nyfletfTp4E6A9P2dZ5g7nMoL90yIw"
    ],
    "value": "AV0Xqspq7jQ5a-dKIZFVGRA0HyejUP60IbJo1DxeiuoY3yFiqm6Ipf5740S0nKFn"
             "KVxk_w3frx4wXOpAGqZUVcfmAN5IdEqzpA0VzDTZASnrSk0vjiHXs97_9rxHMaks"
             "JldqHafzMht3RMboKa7lJxYjWLFnMw2E4JkmmmTPxuwgkLty"
    }
}


r2048privatekey = JWK(**{
    "kid": "example.com:r2048",
    "kty": "RSA",
    "n": "hFWEXArvaZEpSP5qNX7x4C4Hl28GJQTNvnDwkfqiWs63kXbdyPeS06bz6GnY3tfQ"
         "_093nGauWsimqKBmGAGMPtsV83Qxw1OIeO4ujbIIb9pema0qtVqs0MWlHxklZGFk"
         "YfAmbuEUFxYDeLDHe0bkkXbSlB7_t8pCSvc8HLgHjEQjYOlFRwjR0D-uLo-xgsCb"
         "pmCtYkB5lcT_zFgpRgY4zJNLSv7GZiz2S4Fc5ArGjd34lL47-L8bozuYjqNOv9sq"
         "X0Zgll5XaJ1ndvr7UqZu1xQFgm38reoM3IarBP_SkEFbt_v9iak602VO3k28fQhM"
         "aocP7JWR2YLT3kZM0-WTFw",
    "e": "AQAB",
    "d": "Q6iBYpnIrB2mkQZagP1lZuvBv9_osVaSZpLRvKD7DxhvbDTs0coaTJIoVCSB1_VZ"
         "ip8zlUg-TnYWF1Liv9VSwfQ7ddxrcOUtej60mId0ntNz2HhbxJsWjiru8EZoArl0"
         "nEovLDNxlRgRMEyZwOKPC_xHT6nFrk7_s9pR5pEEcubGLAVBKnLCoPdLr-CBjCvW"
         "fJo73W5AZxoSb8MdWQOi5viXHURpr1Y_uBRsMuclovM56Vt05etMsB1AbcTLUDwA"
         "uYrZWa1c08ql60ft7b3v6Q_rCL7EHtFU3PHAuP0mV7tM5BfAPf4T0g9pbr4GOw7e"
         "qQCiYgPFE7gmCR_PDxv5YQ",
    "p": "6DIM343hAtj1hQprJaVQ3T8YeIytIQ7Ma544C0A8BX-irjJfARy4fAlTSyBFeauZ"
         "0WdbMGtKpAIgNVmfCfuP7W1bXw7UaxpqsQlbw54K1VtBs8xG-lee_2YQ3lUlIiC1"
         "at6L0jxWYNkvp-LIfU2F5ZQir5ZWVXwgdMcgoNBABMc",
    "q": "keacq0goV7pAtG2h33OAk-XOSclIF1agvEMMOKuud5V-vGQ6OaYldlYqZmSGgF7R"
         "VlX0GZO70nPqatjd2G-tI8wEq5K_xmLQurUPFW8g___z0CTgJ62KbjFxCtGny5rs"
         "ObX9im6cCc_EOtWZRaApzO8ykxfo1QcEjT4k1na7DzE",
    "dp": "nPmJPnFal2Q5x_GdMlwq6QhI8OaZ_OlWRcM3PFP2v_jj8ERZehUCm8hqKTXuAi2C"
          "1dC8E2XVlj9hqu-l10fcq7Tsurz52laHnpwnD35-8HK7XmRR79jgwuUrrkN90S6v"
          "t0ow2La15s-tqiBlTmDkjqqxMGfAghZiktA0PMPNI-0",
    "dq": "D3c1lkZw2FPK9hVE-m3A7GyIwHOQq8CoCyzER-GS_eQf6hJpxaCiCfg6SF5Rj5v9"
          "brxvwqJRX46gA7F3WrED1m6S9Cj7ISlqXNBCiBAenGRiUOcHx8zyhpnBFNeChOeo"
          "MLnk5V6yNawLbf0kYSgIJkwYvVTkfmhfCCXVO9KcI5E",
    "qi": "wV0NzfCakfog1NFjtPzcga1MtkpizgPkxcP9LjNdvXW2YQZhM6GIEGjsu3ivTrHr"
          "rM-4_bTQHOoTtfIY7wdqBKlwQTJOI0dH9FbNJ4ecGojRwgv83TN8aNKh17Tt44jI"
          "5oibs2P-31B_VW9R1wwhnnOuCYpABfoSbtHIoCRme5I"
})


r2048_rs256_jwk = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "RS256",
        "publicKey": {
            "kty": "RSA",
            "n": "hFWEXArvaZEpSP5qNX7x4C4Hl28GJQTNvnDwkfqiWs63kXbdyPeS06bz6GnY3tfQ"
                 "_093nGauWsimqKBmGAGMPtsV83Qxw1OIeO4ujbIIb9pema0qtVqs0MWlHxklZGFk"
                 "YfAmbuEUFxYDeLDHe0bkkXbSlB7_t8pCSvc8HLgHjEQjYOlFRwjR0D-uLo-xgsCb"
                 "pmCtYkB5lcT_zFgpRgY4zJNLSv7GZiz2S4Fc5ArGjd34lL47-L8bozuYjqNOv9sq"
                 "X0Zgll5XaJ1ndvr7UqZu1xQFgm38reoM3IarBP_SkEFbt_v9iak602VO3k28fQhM"
                 "aocP7JWR2YLT3kZM0-WTFw",
            "e": "AQAB"
        },
        "value": "fiW4-E8CAtqAFhJw3vhloMk8F5JK-rByK7b8H7uOsVnKwl5KFJOVsJIIEO6O5eLY"
                 "maET4ewWr93TWGiVt1WmasgTmU1xgDmUG4O_tvsZeWQ9iJJ4dZ6W1KowlYFx24n6"
                 "eWfOqrJHVl5CZFBYmoQpwkg26yArvBuPJKWDbMPGth4QTtbttkm-rSfr30_mjCQo"
                 "u6F6QhVGxZxeMs7PyeKQnq5qUY2NeCEjCnrIxMPcLP0FXgBRlGfFBLj-HLQOkWLY"
                 "H9LDZ24vj4Z7vZrCRZBa0EehAcRp5cDa2kX_ex-rm02AmbdjxmsWqnL_LKDTzlQc"
                 "iI6t4E6AR27y4f_G7FnrGA"
    }
}


r2048_rs256_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "RS256",
        "keyId": "example.com:r2048",
        "value": "AC8GELBS_2i1KXg8pXMaJwPTF1czAJiLRdj6Fxi85Wm3Eb7nOIMhM1LVE8-9BHeN"
                 "l5lBCoIl1qsEeHly_Ub5J969aWLdHxBoGH_z1aEEDhQUNnQ1mT2kL3J9bwYSL2Lx"
                 "qwpINnh2iDM4FaL3fwRRtMSwcsuXqTVXpS2anvlCShll4EFLSFIG527FCCGH0JMV"
                 "UZmhaOeR7lH2MOsdC-MsZ_7LzKmGgydfaF1xu4u3jmC78H1wSme5Arl7DSNBDFQh"
                 "K2ZqjWIztIkhfZwmxW0OvzUSC3wdXKKNUE53EETIQSoZkTDW8v5_Bz-ebGEF5T7Y"
                 "VwG8M5MZdCE_ZPy-c5tXng"
    }
}


r2048_rs256_imp = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "RS256",
        "value": "JG4PrnwSHk3eBfYRyuKwiybbBnZ-aJWAG0_3-X9eJJg9Xxe_zGHcUiNrH2o77qux"
                 "XcFSykV1LQALyS7blqecOBTRYYEPaMvKYmNNouXphAtCjfTRfK6zrxo8WQW6kHaJ"
                 "h4JQ-_4JZgr7f2r0iMuycnC-1cXQ5YUQsTsqfNXZrI8drWFDNxUGMTzoPx8lcR1V"
                 "5nyZyXMwHdtE84Zy9V2q-Fd38vobcpYzrUJQSweCVr8MiGLWFmLtmknH2ckm6t8S"
                 "45JQr3zjHHrE42_9BqN4o7ggNoHfMAeZYIn09EBdpD0EwCXZ-Kti2VTSl3X-wHfb"
                 "kLrScKWFuAa6i8BuZrEZBg"
    }
}

r2048_rs256_cer = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "RS256",
        "certificatePath": [
            "MIICxDCCAiOgAwIBAgIGAWFcc5ruMAwGCCqGSM49BAMEBQAwLTELMAkGA1UEBhMC"
            "RVUxHjAcBgNVBAMTFVRydXN0IE5ldHdvcmsgU3ViIENBMzAeFw0xODAxMDEwMDAw"
            "MDBaFw0yMjEyMzEyMzU5NTlaMDIxCzAJBgNVBAYTAkZSMQ0wCwYDVQQFEwQ0NTAx"
            "MRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC"
            "AQoCggEBAIRVhFwK72mRKUj-ajV-8eAuB5dvBiUEzb5w8JH6olrOt5F23cj3ktOm"
            "8-hp2N7X0P9Pd5xmrlrIpqigZhgBjD7bFfN0McNTiHjuLo2yCG_aXpmtKrVarNDF"
            "pR8ZJWRhZGHwJm7hFBcWA3iwx3tG5JF20pQe_7fKQkr3PBy4B4xEI2DpRUcI0dA_"
            "ri6PsYLAm6ZgrWJAeZXE_8xYKUYGOMyTS0r-xmYs9kuBXOQKxo3d-JS-O_i_G6M7"
            "mI6jTr_bKl9GYJZeV2idZ3b6-1KmbtcUBYJt_K3qDNyGqwT_0pBBW7f7_YmpOtNl"
            "Tt5NvH0ITGqHD-yVkdmC095GTNPlkxcCAwEAAaNdMFswCQYDVR0TBAIwADAOBgNV"
            "HQ8BAf8EBAMCA_gwHQYDVR0OBBYEFIGmjEZHXHRSGub_c6jTyxuZClVHMB8GA1Ud"
            "IwQYMBaAFNRatLnioLY2AbdQrqtUCvSBtDQxMAwGCCqGSM49BAMEBQADgYwAMIGI"
            "AkIA57GembY0hb9d_Qx2ZJRfFqoR_Q1S87xSx_AUK2xnuZgaclPKv6q4GT5sFD1V"
            "1DxbLUnM3q1yYCPZUQBAeeab-UYCQgEV-HvFgA8de7dKOQzpGRQ9FHLdhlT1dYsr"
            "IxjziZkleFLUgs01-fV-ITx5RMeT9w681je1LW2aQK5_nRrErARerw",
            "MIIDsTCCAZmgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAuMQswCQYDVQQGEwJVUzEf"
            "MB0GA1UEAxMWVHJ1c3QgTmV0d29yayBSb290IENBMTAeFw0xNjA3MTAxMDAwMDBa"
            "Fw0yNTA3MTAwOTU5NTlaMC0xCzAJBgNVBAYTAkVVMR4wHAYDVQQDExVUcnVzdCBO"
            "ZXR3b3JrIFN1YiBDQTMwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGJzPZsjniw"
            "yZeXrgrlQM3Y13r3znR8FSQpKbC2bplrOWySQJPGm-GFObe5Dk4t3Jrtk_Pbs8-3"
            "VW_4q5drL0YqYwBYNJPhqjbSM6SGHrc6wNdPZRw_WnJVa0ELXKICC73lkjskWPfE"
            "-cLpZ3sTq1ovEmoNjgaySVRUH1wFDdkqyReJaKNjMGEwDwYDVR0TAQH_BAUwAwEB"
            "_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNRatLnioLY2AbdQrqtUCvSBtDQx"
            "MB8GA1UdIwQYMBaAFEkmC1HDAh0fXehpiUhUGE868Hk2MA0GCSqGSIb3DQEBDQUA"
            "A4ICAQAs2KADYyGQCVy8tJZWakNtGdww4OumZpBuR66p_2xK7veRubQEhG-nJn7o"
            "VkJ4w5pEec3sYQEqtPbHyZcEKEYbOJ2cVf1nMH-DvFZ6ypQocGRp3WSWsTzL3Sgq"
            "iWrQdPX1Y5dO6Hvx7p9ST9H2WgkxB-Q75Jov1gVF3bScAbxb7Mw7tf5z3Cvqmfo0"
            "Gatkgzz6-jDPrtUK7AAAOw3C0kHMbE3EnNarsfhBkUerE8QVmHIvz373mWt0Sngu"
            "aHq0A9ZuSia_pF7bgfVRZi2ZzIzpu2O276sB2Yji9tcSn5l21jq63rXtvY_DLAi4"
            "kaLyf9sHT_tkH-gkTdkdkfQq8sA5ysRW21wPQbmjTIVwsfY4JjajVIUitjPbkUJq"
            "URpf2VD0JXdYQHS6KVPWqHWTlKPlsKbhw4ghuLqCMYda88L9rxWnSC5L8s0DJSuB"
            "Bm-nq23NtHl5FbCzeXWcKRayIgimT-An1WIOeJP4F7-BctYLIooKoQzJZR1tOWvp"
            "rUs22_xAivVBz7J_LmJyVlKesB2ic8qYdt7YVoCsWrnEUgoNoJPwLHeva8KPvd0g"
            "LXrwaMyTCCjeoemXFj6nCbbMHJeVffh6jYBAzlbcAEvTiZcdzrVVr54kOtWskyae"
            "DnAcMXW4Of1vWdUJ2as5nyfletfTp4E6A9P2dZ5g7nMoL90yIw"
        ],
        "value": "ANp5RuiwVkpwvo_AvAhGhYGtCYDAaR0cOPTuG8J7VxswMTiHKf8LvLeC1QljtV0o"
                 "VKX8PaQe9GIo1xnqGlRt4hZbjwEnxMmO_lVvjlChTxHE4N7YICFjMrkJI0cWkFyk"
                 "hvr2eaWOcrcit8bezPpmwH6BUlEGoGPrrKZTmKFPYnsUkNnbc4DUNvpAr0XYZTfj"
                 "Weiy9G9ed-8Q04JXO7lXhluVnhe-MeXvjAZ8GoX3jaJBWQ_Y46ILCn8mLMw0R1Ps"
                 "eE3frnyzhrMWHYWtgJam0JwSrKDn_BSf-w8J36BT_V7xymlH_MeKE2g5vsfY3IpL"
                 "NULY1ynfCdaW3tY0_qcaig"
    }
}


a256bitkey = JWK(**{
    "kid": "a256bitkey",
    "kty": "oct",
    "alg": "HS256",
    "k": base64url_encode(unhexlify("7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a"))
})


a256_hs256_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "HS256",
        "keyId": "a256bitkey",
        "value": "GJ6Jhb-PfHpN6KPcjHBNxbO9j56ShgUh13JfmZ3ORkI"
    }
}


a384bitkey = JWK(**{
    "kid": "a384bitkey",
    "kty": "oct",
    "alg": "HS384",
    "k": base64url_encode(unhexlify("37b7daeedc3403eb865a506c19597a37582ad5059e08438ada8bf544ee44bb30"
                                    "24a15f8fa191bbe7a533a56c9fc1db1d"))
})


a384_hs384_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "HS384",
        "keyId": "a384bitkey",
        "value": "FjkRAZS-HsGsC_WPKsF2fmaNO7CPp90asbgXfOPQjolyK_qQaOuJH_u7PgonjzN9"
    }
}


a512bitkey = JWK(**{
    "kid": "a512bitkey",
    "kty": "oct",
    "alg": "HS512",
    "k": base64url_encode(unhexlify("83d26e96b71a5dd767c215f201ef5884fb03dfe5a8ee9612d4e3c942e84d45df"
                                    "dc5801cb8379958f3af600d68eba1a14e945c90f1655671f042cea7b34d53236"))
})


a512_hs512_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "algorithm": "HS512",
        "keyId": "a512bitkey",
        "value": "VJHJXrZhVMMWTKTJktmdE5J4xBjKwtdf25eItui4fIGuyYsiZD5M9n573WZ0XgM9q48gG1KpTee4q8LCW4a7qQ"
    }
}

p256_es256_r2048_rs256_mult_jwk = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "signers": [{
            "algorithm": "ES256",
            "publicKey": {
                "kty": "EC",
                "crv": "P-256",
                "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
                "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY"
            },
            "value": "yI_ucBjb2uOGK07B5y5swXmTRO8jqrCAktE4mQlxLhc05hAksE-MuSEgnO14InBy"
                     "LcxWwe2xp6qXDQZlOHjFAg"
        },{
            "algorithm": "RS256",
            "publicKey": {
                "kty": "RSA",
                "n": "hFWEXArvaZEpSP5qNX7x4C4Hl28GJQTNvnDwkfqiWs63kXbdyPeS06bz6GnY3tfQ"
                     "_093nGauWsimqKBmGAGMPtsV83Qxw1OIeO4ujbIIb9pema0qtVqs0MWlHxklZGFk"
                     "YfAmbuEUFxYDeLDHe0bkkXbSlB7_t8pCSvc8HLgHjEQjYOlFRwjR0D-uLo-xgsCb"
                     "pmCtYkB5lcT_zFgpRgY4zJNLSv7GZiz2S4Fc5ArGjd34lL47-L8bozuYjqNOv9sq"
                     "X0Zgll5XaJ1ndvr7UqZu1xQFgm38reoM3IarBP_SkEFbt_v9iak602VO3k28fQhM"
                     "aocP7JWR2YLT3kZM0-WTFw",
                "e": "AQAB"
            },
            "value": "aF3qTpIFGcJxB5En-JFQZWGqX-vOoGrs27SKBz_mNjmJRDdAeE-0NnmF16elUh2Y"
                     "mFWFfZd_SLnbrlkKE2adlOqxqWiQYcB1smKSOQ3dTwAYLcD4ebuBgDBKRs9ZO_GP"
                     "BeSpwH5FGpUQbSPGh7BWD69OPF6Ik5vHPikfls-fr1qgrxpYARY1vUhXvl-QFtBv"
                     "nd3Xn_n63kFQl4GZDeP6TZyuoaulTKsFBvhHu0OfqknoOzEUYJYMhS9r5rDz_AVb"
                     "nx_F1Key-gQnm6UmuVothu_ApYy_NW4HEVKZfxhU_nYzuGYQD9VUI9WYmstBcLyS"
                     "3uNPHDECoEy0hQ4UpZPMBg"
        }]
    }
}


p256_es256_r2048_rs256_mult_exts_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "signers": [{
            "algorithm": "ES256",
            "keyId": "example.com:p256",
            "otherExt": "Cool Stuff",
            "https://example.com/extension": {
                "life-is-great": True
            },
            "value": "T-7QWCI4GDMutdCOi4MDca_6Jpq2YLasrfOduvYgt8YlqVlY9gYrNfotLN3JjQbC"
                     "rW6ShIrhErUY0sJ9VGBseg"
        },{
            "algorithm": "RS256",
            "keyId": "example.com:r2048",
            "otherExt": "Other Data",
            "value": "fEy3hW0MXzpK9kC_gjPtpVBXBdBkuVVoY8DMugjMTJBw2t5iABpH_oNKmp3LQl-z"
                     "B0LcSpINh0bRgv2sErgPFHEH0fcg1omJ8N7jee4yPkA4-r9qW_vWOKAOQOArcUno"
                     "GYtQTcOMlaNz5B-qbn-aX0faxm3zGOrizWVdQTG7fJe8dQW4M3JdGy01zlA37fpX"
                     "9ucKvM2nKkSZtAjFRtKA504UEbww3wLcQlbocZPpVpYoaiN_Oi6X7zpIhxvTbYR1"
                     "bhh9D9uuXaaYSIG5VjokpVo0vTvhrMg4rT29QRq70RyH45cA_ydwr18gwHLvXU0-"
                     "4lSkB_d1F7f7rjwRnMlwAw"
        }],
        "extensions": ["otherExt", "https://example.com/extension"]
    }
}

p256_es256_r2048_rs256_mult_excl_kid = {
    "mySignedData": "something",
    "myUnsignedData": "something else",
    "signature": {
        "signers": [{
            "algorithm": "ES256",
            "keyId": "example.com:p256",
            "value": "4TNtGVbvViLLvHnxK-_V_yCdCljWyDBCgKLFV5109OXNu78gKxPbKERqIPwJ_pr2"
                     "-rx7_nsHXk4cLzuPW8B8UQ"
        },{
            "algorithm": "RS256",
            "keyId": "example.com:r2048",
            "value": "gi4VgggTcn1jKAFANRBK9a8BLN5oIlABLdZERnhHTDY31l57P26WbY5Q7ACqE9w2"
                     "4BE6cRXEDACD3gLFsGIEPhu3EOE38fWWkR-5Y9hfGSJO64vSFxVEktYsf5XKyeCT"
                     "tMLApmJu1wjggmB5UuC1gKuecy0ChnfJFnrPE46B9TLGOoYskjEqGJRlgPHvvqo7"
                     "euFkDM61Wz1vggIq-xfqih_FYgz42280Yy2HzE-GDZXTNfji1ka7DTjujLnCjfLA"
                     "Qa7-65H60KFHnrMULe6k9PZiwfoSykMm3TYOF-c9hWdjwpbqOBeB-CPOg92ACBSh"
                     "6cOtcHqVGVTqW_-9hj0G_w"
        }],
        "excludes": ["myUnsignedData"]
    }
}


p256_es256_r2048_rs256_chai_jwk = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "chain": [{
            "algorithm": "ES256",
            "publicKey": {
                "kty": "EC",
                "crv": "P-256",
                "x": "censDzcMEkgiePz6DXB7cDuwFemshAFR90UNVQFCg8Q",
                "y": "xq8rze6ewG0-eVcSF72J77gKiD0IHnzpwHaU7t6nVeY"
            },
            "value": "z3YILoyx1GURBuQaF6Oo9XBIOEXfzeulkq_8kDyXGo3raAmGMLiRTsyqwgLFHNMu"
                     "ih41GIdmYfJ4zs7pvtF6uA"
            },{
                "algorithm": "RS256",
                "publicKey": {
                    "kty": "RSA",
                    "n": "hFWEXArvaZEpSP5qNX7x4C4Hl28GJQTNvnDwkfqiWs63kXbdyPeS06bz6GnY3tfQ"
                         "_093nGauWsimqKBmGAGMPtsV83Qxw1OIeO4ujbIIb9pema0qtVqs0MWlHxklZGFk"
                         "YfAmbuEUFxYDeLDHe0bkkXbSlB7_t8pCSvc8HLgHjEQjYOlFRwjR0D-uLo-xgsCb"
                         "pmCtYkB5lcT_zFgpRgY4zJNLSv7GZiz2S4Fc5ArGjd34lL47-L8bozuYjqNOv9sq"
                         "X0Zgll5XaJ1ndvr7UqZu1xQFgm38reoM3IarBP_SkEFbt_v9iak602VO3k28fQhM"
                         "aocP7JWR2YLT3kZM0-WTFw",
                    "e": "AQAB"
            },
            "value": "G0ZEFIhcsVPG5r7-XMNjruXXvN7V63H9dnAVzcrsbwWk9Z8x9fIjT0UEazsWzpMv"
                     "gKRsDayuMk6WIl7nOYiDrTOM6C_BI0U7jDxrK7dunIGQ-z5RN6pvF4Q27mOHx7yj"
                     "VVsPBN5VTl4JVT6HQnfpzPe1uZiFRG2hw5BYZa-vvkBcZb6bWOClTsn2i7zLQbVA"
                     "-5vTGa7zJtOmuLwBEf_GFf_o3pN0Bjx94S87KwoaWfLAaBPMgFZIDoNGgW5hmBJj"
                     "1-YKp4l9WgsX2I7M8rvg5ptEupV9HDRiH3kivybUHDibOoun1-D1bkKRgA447ug1"
                     "gxrvpI3dSLKb-QQd4j7b7A"
        }]
    }
}


p256_es256_r2048_rs256_chai_ext_kid = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
    "signature": {
        "chain": [{
            "algorithm": "ES256",
            "keyId": "example.com:p256",
            "otherExt": "Cool Stuff",
            "https://example.com/extension": {
                "life-is-great": True
            },
            "value": "sQGISSMlWQACetPXZmeG_8bnFmBOnHAH58o9E3vkMf7czyjxa2bFQZpEuf3pp1VP"
                     "T0dWPMKY30thKw7PoHs6mQ"
        },{
            "algorithm": "RS256",
            "keyId": "example.com:r2048",
            "otherExt": "Other Data",
            "value": "T9xlcO-jalkA9DS8ybTCKuNWnjge8-QALxQXOSEc0STsaTKDtgFixh_DwzHUZndi"
                     "I0fE529dD0j7Zr5T0NM53VqztlM-jDHw7hy_MJKn6szJdlH5dYmLR7_QY6QK_wMl"
                     "trA0qqCh36e_AI8J1ivHOodIDSitizYldI6v_tmaDkvXLIjSwsCVPVJmR19iis6b"
                     "d5hdVAh8HeJAjk7plx-hDKO08FkA0dIIB0F-PZIe1FaLkMfIEto9OFtxTTacSauE"
                     "RV_o-lZRXNOOA_2Hnfp2BC4W4lswhTMIw-eWPEaJl510AAINuASBu0D7U-PwtcKG"
                     "8VKiw17JX6NaMjEQNbDwuA"
        }],
        "extensions": ["otherExt", "https://example.com/extension"]
    }
}


def make_tuples(spec):
    for key, objs in spec:
        for obj in objs:
            yield key, obj


@pytest.mark.parametrize('key,obj', make_tuples([
    (p256privatekey,  [p256_es256_jwk,  p256_es256_kid,  p256_es256_imp,  p256_es256_cer,
                       p256_es256_r2048_rs256_mult_jwk]),
    (p384privatekey,  [p384_es384_jwk,  p384_es384_kid,  p384_es384_imp,  p384_es384_cer]),
    (p521privatekey,  [p521_es512_jwk,  p521_es512_kid,  p521_es512_imp,  p521_es512_cer]),
    (r2048privatekey, [r2048_rs256_jwk, r2048_rs256_kid, r2048_rs256_imp, r2048_rs256_cer,
                       p256_es256_r2048_rs256_mult_jwk]),
    (a256bitkey,      [a256_hs256_kid]),
    (a384bitkey,      [a384_hs384_kid]),
    (a512bitkey,      [a512_hs512_kid]),
    ]))
def test_verify_key_succeeds(key, obj):
    jsf = JSF(obj)
    jsf.verify('signature', key=key)


@pytest.mark.parametrize('key,obj', make_tuples([
    (p256privatekey,  [p256_es256_jwk,  p256_es256_kid,  p256_es256_imp,  p256_es256_cer,
                       p256_es256_r2048_rs256_mult_jwk]),
    (p384privatekey,  [p384_es384_jwk,  p384_es384_kid,  p384_es384_imp,  p384_es384_cer]),
    (p521privatekey,  [p521_es512_jwk,  p521_es512_kid,  p521_es512_imp,  p521_es512_cer]),
    (r2048privatekey, [r2048_rs256_jwk, r2048_rs256_kid, r2048_rs256_imp, r2048_rs256_cer,
                       p256_es256_r2048_rs256_mult_jwk]),
    (a256bitkey,      [a256_hs256_kid]),
    (a384bitkey,      [a384_hs384_kid]),
    (a512bitkey,      [a512_hs512_kid]),
    ]))
def test_verify_key_fails(key, obj):
    modified = copy(obj)
    modified['name'] = 'Jane'
    jsf = JSF(modified)
    with pytest.raises(InvalidJWSSignature):
        jsf.verify('signature', key=p256privatekey)


@pytest.mark.parametrize('obj', [p256_es256_jwk, p384_es384_jwk, p521_es512_jwk,
                                 r2048_rs256_jwk, p256_es256_r2048_rs256_mult_jwk])
def test_verify_jwk_succeeds(obj):
    jsf = JSF(obj)
    jsf.verify('signature')


@pytest.mark.parametrize('obj', [p256_es256_jwk, p384_es384_jwk, p521_es512_jwk,
                                 r2048_rs256_jwk, p256_es256_r2048_rs256_mult_jwk])
def test_verify_jwk_fails(obj):
    modified = copy(obj)
    modified['name'] = 'Jane'
    jsf = JSF(modified)
    with pytest.raises(InvalidJWSSignature):
        jsf.verify('signature')


def test_verify_named():
    jsf = JSF(p256_es256_name)
    jsf.verify('authorizationSignature')


@pytest.mark.parametrize('obj', [p256_es256_exts, p256_es256_r2048_rs256_mult_exts_kid,
                                 p256_es256_r2048_rs256_chai_ext_kid])
def test_verify_extensions(obj):
    jsf = JSF(obj)
    with pytest.raises(InvalidJWSSignature) as e:
        jsf.verify('signature')
    assert 'Unknown extension' in str(e.value)


@pytest.mark.parametrize('key,obj', [
    (None, p256_es256_excl),
    (p256privatekey, p256_es256_r2048_rs256_mult_excl_kid),
    (r2048privatekey, p256_es256_r2048_rs256_mult_excl_kid)])
def test_verify_excluded_intact_succeeds(key, obj):
    jsf = JSF(obj)
    jsf.verify('signature', key=key)


@pytest.mark.parametrize('key,obj', [
    (None, p256_es256_excl),
    (p256privatekey, p256_es256_r2048_rs256_mult_excl_kid),
    (r2048privatekey, p256_es256_r2048_rs256_mult_excl_kid)])
def test_verify_excluded_modified_succeeds(key, obj):
    modified = copy(obj)
    modified['myUnsignedData'] = 'foo bar'
    jsf = JSF(modified)
    jsf.verify('signature', key=key)


@pytest.mark.parametrize('key,obj', [
    (None, p256_es256_excl),
    (p256privatekey, p256_es256_r2048_rs256_mult_excl_kid),
    (r2048privatekey, p256_es256_r2048_rs256_mult_excl_kid)])
def test_verify_excluded_modified_fails(key, obj):
    modified = copy(obj)
    modified['mySignedData'] = 'foo bar'
    jsf = JSF(modified)
    with pytest.raises(InvalidJWSSignature):
        jsf.verify('signature', key=key)


def test_verify_chain():
    jsf = JSF(p256_es256_r2048_rs256_chai_jwk)
    jsf.verify('signature')
