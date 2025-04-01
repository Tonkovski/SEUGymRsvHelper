"""CaptchaKiller.py

Scratched by t0nkov

Usage:
    from CaptchaKiller import CaptchaKiller
    killer = CaptchaKiller('your_api_key')
    killer.updatekey('your_api_key')
    killer.solveCaptcha()
"""

import requests
import ddddocr
import json
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import time
import random

class CaptchaSliderKiller: # wip
    """Class to tackle SEU gym slider CAPTCHA using ddddocr."""

    _url_gencaptcha = 'https://dndxyyg.seu.edu.cn/yy-sys/captcha/genCaptcha'
    _url_checkcaptcha = 'https://dndxyyg.seu.edu.cn/yy-sys/captcha/checkCaptcha'

    def __init__(self,
                 api_key: str = '',
                 canvas_width: int = 300,
                 canvas_height: int = 180,
                 rsvsess: requests.Session = None): # wip
        self.token = api_key
        self.dwidth = canvas_width
        self.dheight = canvas_height

        if rsvsess:
            self.sess = rsvsess
        else:
            self.sess = requests.Session()
            self.sess.headers.update({
                'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                            'AppleWebKit/537.36 (KHTML, like Gecko) '
                            'Chrome/58.0.3029.110 Safari/537.3')
            })
        
        self.ocr = ddddocr.DdddOcr(ocr=False, det=False, show_ad=False)
        self.captchabg = None
        self.captchajigsaw = None

    def updateKey(self, api_key: str):
        """Update the API key for the session.

        Args:
            api_key (str):    API key for CAPTCHA session, corresponds to
                              Bearer token in reservation session.
        """
        
        self.token = api_key

    def solveCaptcha(self,
                     fake_op: bool = False,
                     enc_id: bool = True) -> dict:
        """Request and solve a CAPTCHA.

        Args:
            fake_op (bool):  Simulate fake waiting period. Disabled by default.
            enc_id (bool):   Enable Captcha ID encryption in payload.
                             Set to True by default according to API design.

        Returns:
            dict:       Captcha response id and code.
        """
        
        if not self.token:
            raise ValueError("API key is required.")
        query = {'token': self.token}
        resp = self.sess.post(self._url_gencaptcha, params=query)

        raw_captcha_data = json.loads(resp.text)
        captchabg_b64 = raw_captcha_data['captcha']['backgroundImage']
        captchajigsaw_b64 = raw_captcha_data['captcha']['templateImage']
        self.captchabg = base64.b64decode(captchabg_b64.split(',')[1])
        self.captchajigsaw = base64.b64decode(captchajigsaw_b64.split(',')[1])
        res = self.ocr.slide_match(self.captchabg, self.captchajigsaw,
                                   simple_target=True)
        deltax = int(res['target'][0]
                     / raw_captcha_data['captcha']['backgroundImageWidth']
                     * self.dwidth)

        trail = self._trailGen(deltax, fake_op)
        timestart = time.time()
        timeend = timestart + trail[-1]['t'] / 1000
        str_timestart = (
            time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(timestart)) +
            f"{timestart:.3f}".split('.')[1] + "Z"
        )
        str_timeend = (
            time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(timeend)) +
            f"{timeend:.3f}".split('.')[1] + "Z"
        )

        payload = {
            'id': raw_captcha_data['id'],
            'data': {
                'bgImageWidth': self.dwidth,
                'bgImageHeight': self.dheight,
                'startTime': str_timestart,
                'stopTime': str_timeend,
                'trackList': trail
            }
        }
        resp = self.sess.post(self._url_checkcaptcha,
                       data=json.dumps(payload),
                       params=query)
        
        respdata = json.loads(resp.text)
        if respdata['success'] == False:
            return {}
        elif enc_id:
            return self._encCaptchaPayload(json.loads(resp.text)['data'])
        else:
            return json.loads(resp.text)['data']

    def _trailGen(self, delta: int, fake_op: bool) -> list:
        """Generate simulated trail of movements for slide captcha.

        Args:
            delta (int):    Horizontal pixel distance to slide.
            fake_op (bool): Simulate waiting period.

        Returns:
            list:   List of movements.
        """

        timetrail = random.randint(100, 500)
        x, y = 0, 0
        track_list = [{
            'x': x, 'y': y, 'type': "down", 't': timetrail
        }]
        timetrail += random.randint(25, 50)

        while x <= delta:
            if random.random() > 0.1:
                timetrail += random.randint(1, 5)
                x += random.randint(1, 3)
                track_list.append({
                    'x': x, 'y': y, 'type': "move", 't': timetrail
                })
            else:
                timetrail += random.randint(1, 3)
                y += 1
                track_list.append({
                    'x': x, 'y': y, 'type': "move", 't': timetrail
                })
        if track_list[-1]['t'] < 300:
            timetrail += random.randint(300,310) - timetrail
            track_list[-1]['t'] = timetrail
        timetrail += random.randint(25, 50)
        track_list.append({
            'x': x, 'y': y, 'type': "up", 't': timetrail
        })
        
        if fake_op:
            time.sleep(timetrail / 1000)

        return track_list

    def _encCaptchaPayload(self, captcha_payload: dict) -> dict:
        """Encrypt captcha response.

        Args:
            captcha_payload (dict):    Payload to be encrypted.
        
        Returns:
            dict:   Encrypted payload.
        """
        
        t = captcha_payload['captchaId'][:16].encode('utf-8')
        n = captcha_payload['captchaId'][1:17].encode('utf-8')
        ciphersuite = AES.new(t, AES.MODE_CBC, iv=n)
        
        paddingtext = pad(captcha_payload['captchaCode'].encode('utf-8'),
                          AES.block_size)
        encrypted_code = ciphersuite.encrypt(paddingtext)
        enc_payload = {
            'captchaId': captcha_payload['captchaId'],
            'captchaCode': base64.b64encode(encrypted_code).decode('utf-8')
        }
        
        return enc_payload
