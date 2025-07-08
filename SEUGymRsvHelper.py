import requests

import json
import re
import pickle

import datetime
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

from CaptchaKiller import CaptchaSliderKiller

def _logprint(log):
    curr_time = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print('[%s] %s' % (curr_time, log))

def _logerrorExit(log):
    _logprint(log)
    # input('Press Enter to quit...\n')
    exit(1)

class SEUGymRsvHelper:
    
    _path_config = 'config.json'
    _path_cookiejar = 'cookiejar.pkl'

    _url_getpubkey = 'https://auth.seu.edu.cn/auth/casback/getChiperKey'
    _url_caslogin = 'https://auth.seu.edu.cn/auth/casback/casLogin'
    _url_verifytgt = 'https://auth.seu.edu.cn/auth/casback/verifyTgt'

    _url_gym_home = 'https://dndxyyg.seu.edu.cn/yy-sys/pc/home'
    _url_gym_login = 'https://dndxyyg.seu.edu.cn/sso/login'
    _url_gym_auth = 'https://dndxyyg.seu.edu.cn/sso/oauth2/authorize'
    _url_gym_oidc = 'https://dndxyyg.seu.edu.cn/yy-sys/oidc-callback'
    _url_gym_iam = 'https://dndxyyg.seu.edu.cn/bus/graphql/iam'
    _url_gym_sysquery = 'https://dndxyyg.seu.edu.cn/bus/graphql/apps_yy_sys'


    def __init__(self):
        self.sess = requests.Session()
        self.sess.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/58.0.3029.110 Safari/537.3'),
            'Content-Type': 'application/json'
        })

        _logprint('Loading config...')
        self.config = self._loadConfig()
        if self._loadCookie():
            _logprint('Using cookies from previous session.')
        else:
            _logprint('No cookies found from previous session.')

        self.id_tk = ''
        self.bearer_tk = ''
        self.userinfo = {}
        self.login()
        self.auth()
        self.captcha_killer = CaptchaSliderKiller(self.bearer_tk,
                                                  rsvsess=self.sess)
        
        
    def _loadConfig(self) -> dict:
        with open(self._path_config, 'r') as config_file:
            return json.load(config_file)
    
    def _loadCookie(self) -> bool:
        try:
            with open(self._path_cookiejar, 'rb') as cookiejar_file:
                self.sess.cookies.update(pickle.load(cookiejar_file))
            return True
        except (FileNotFoundError, EOFError):
            return False

    def _updateSavedCookies(self):
        with open(self._path_cookiejar, 'wb') as cookiejar_file:
            pickle.dump(self.sess.cookies, cookiejar_file)

    def login(self):
        if self._isLogin():
            _logprint('Active login session restored.')
            return
        else:
            _logprint('Session expired, using config credential to login...')

        _logprint('Requesting public key...')
        resp = self.sess.post(self._url_getpubkey)
        pubKeyText = ('-----BEGIN RSA PUBLIC KEY-----\n' +
                      json.loads(resp.text)['publicKey']
                      .replace('-', '+')
                      .replace('_', '/') +
                      '\n-----END RSA PUBLIC KEY-----')
        pubKey = RSA.import_key(pubKeyText)
        encModule = PKCS1_v1_5.new(pubKey)
        password = self.config['passwd'].encode()
        enc_password = encModule.encrypt(password)
        encb64_passwd = base64.b64encode(enc_password).decode()

        _logprint('CAS logging in...')
        payload = {
            'captcha': '',
            'loginType': 'account',
            'mobilePhoneNum': '',
            'mobileVerifyCode': '',
            'password': encb64_passwd,
            'rememberMe': True,
            'service': '',
            'username': self.config['username'],
            'wxBinded': False
        }
        resp = self.sess.post(self._url_caslogin, data=json.dumps(payload))
        respdata = json.loads(resp.text)
        if not json.loads(resp.text)['success']:
            _logerrorExit('Login failed with response:\n%s' % respdata)
        _logprint('Login success.')
        self._updateSavedCookies()

    def _isLogin(self) -> bool:
        resp = self.sess.post(self._url_verifytgt, data=json.dumps({}))
        return json.loads(resp.text)['success']

    def auth(self):

        _logprint('Verifying TGT...')
        payload = {'service': self._url_gym_login}
        resp = self.sess.post(self._url_verifytgt, data=json.dumps(payload), allow_redirects=False)
        redr_url = json.loads(resp.text)['redirectUrl']
        resp = self.sess.get(redr_url)

        _logprint('Intercepting tokens...')
        resp = self.sess.get(self._url_gym_home)
        query = {
            'client_id': 'ePmSCRT2MsHl7ZdSxlbL',
            'redirect_uri': '%s?retUrl=%s' % (self._url_gym_oidc,
                                              self._url_gym_home),
            'response_type': 'id_token token',
            'scope': ('data openid process task app submit process_edit '
                      'start profile')
        }
        resp = self.sess.get(self._url_gym_auth,
                             params=query,
                             allow_redirects=False)
        
        redr_url = resp.headers['Location']
        acc_tk_pattern = re.compile(r'access_token=(.{32})')
        id_tk_pattern = re.compile(r'id_token=([A-Za-z0-9-_.]+)&')
        self.bearer_tk = acc_tk_pattern.search(redr_url).group(1)
        self.id_tk = id_tk_pattern.search(redr_url).group(1)
        self.sess.headers.update({
            'Authorization': ('Bearer %s' % self.bearer_tk)
        })
        self.sess.get(resp.headers['Location'])

        _logprint('Checking service auth status...')
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': None,
            'variables': {},
            'query': (
                '{\n  me {\n    account\n    accountFriendly\n    active\n    activeTime\n    birthday\n    cardNo\n    cardType\n    createDataSource\n    createSource\n    createTime\n    dataSource\n    description\n    disabled\n    email\n    express\n    id\n    ip\n    name\n    openid\n    phone\n    sex\n    source\n    tags\n    tenantId\n    timestamp\n    username\n    attrsValues {\n      code\n      key\n      value\n    }\n    positions {\n      dept {\n        id\n        name\n        code\n        parent\n        tags\n        treeType\n        tenantId\n        timestamp\n        disabled\n        source\n        description\n      }\n      post {\n        id\n        name\n        code\n        tags\n        formal\n        tenantId\n        timestamp\n        disabled\n        source\n        description\n      }\n    }\n  }\n}\n'
            )
        }
        resp = self.sess.post(self._url_gym_iam,
                              params = query,
                              data = json.dumps(payload))
        respdata = json.loads(resp.text)['data']['me']
        if resp.status_code != 200:
            _logerrorExit('Authorization failed with response:\n%s' % resp.text)
        else:
            _logprint('Successfully authorized as: [%s].' % respdata['account'])
        self.userinfo = respdata
        self._updateSavedCookies()

    def _checkTenantStatus(self) -> dict:
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'checkTenantStatus',
            'query': (
                'query checkTenantStatus {\n  '
                    'checkTenantStatus {\n    '
                        'errcode\n    '
                        'msg\n    '
                        'msg_en\n  '
                    '}\n'
                '}\n'),
            'variables': {}
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        return json.loads(resp.text)

    def _getCampusList(self):
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'findCodeItemsAll',
            'query': (
                'query findCodeItemsAll('
                                        '$code_id: String, '
                                        '$code: String, '
                                        '$item_parent: String'
                ') {\n  '
                    'findCodeItemsAll('
                                      'code_id: $code_id, '
                                      'code: $code, '
                                      'item_parent: $item_parent'
                    ') {\n    '
                        'id\n    '
                        'codes_id\n    '
                        'item_code\n    '
                        'item_name\n    '
                        'item_description\n    '
                        'item_index\n    '
                        'item_level\n    '
                        'item_parent\n    '
                        'create_time\n  '
                    '}\n'
                '}\n'),
            'variables': {'code': 'yy_'}
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        return json.loads(resp.text)

    def _getResourceTypeId(self, resource_name: str) -> str:
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'findResourcesTypeAllByAccount',
            'query': (
                'query findResourcesTypeAllByAccount($filter: ResourcesTypeFilterMap) {\n  findResourcesTypeAllByAccount(filter: $filter) {\n    id\n    resources_name\n    resources_name_en\n    resources_tag\n    resources_tag_en\n    icon\n    icon_not\n    created_user\n    created_user_name\n    state\n    can_location\n    is_appointment_number_limit\n    appointment_number_rule\n    appointment_number_limit\n    timeperiod_number_begin_date\n    timeperiod_number_end_date\n    is_incomplete_appointment_number_limit\n    incomplete_appointment_number_limit\n    common_enable\n    cyclicity_enable\n    batch_enable\n    default_appointment_state\n    punctuality_rule\n    deviation_minutes\n    earliest_punctuality_rule\n    earliest_deviation_minutes\n    holding_minutes\n    can_appointment_remark\n    capacity_field_type\n    sign_out_rule\n    open_captcha_verify\n    open_frequency_verify\n    resource_open_mode\n    wemeet_enable\n    order\n    del\n    create_time\n    start_time\n    end_time\n    appointment_category\n    extendedProperties {\n      id\n      resources_type_id\n      extended_properties_code\n      extended_properties_name\n    }\n    resourcesTypeAuthList {\n      id\n      resources_type_id\n      resources_type_name\n      grant_object_id\n      grant_object_name\n      grant_object_type\n      grant_time\n      operate_user_id\n      operate_user_name\n    }\n  }\n}\n'
            ),
            'variables': {}
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        resp_data = json.loads(resp.text)
        resource_list = resp_data['data']['findResourcesTypeAllByAccount']
        for r in resource_list:
            if r['resources_name'] == resource_name:
                return r['id']
        raise ValueError('Resource type [%s] not found.' %
                         resource_name)

    def queryShowResourceList(self, resource_name: str):
        resource_type_id = self._getResourceTypeId(resource_name)
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'findResourcesAllByAccount',
            'query': (
                'query findResourcesAllByAccount($first: Int, $offset: Int, $typeId: String, $typeName: String, $resourceName: String, $bookDate: String, $bookStartTime: String, $bookEndTime: String, $item_name: [String], $is_cyclicity: String, $cyclicity_start_date: String, $cyclicity_end_date: String, $cyclicity_start_time: String, $cyclicity_end_time: String, $cyclicity_strategy: String, $cyclicity_weekList: [String], $cyclicity_dayList: [String], $order_by: String, $cur_language: String, $filter: ResourcesFilterMap) {\n  findResourcesAllByAccount(first: $first, offset: $offset, typeId: $typeId, typeName: $typeName, resourceName: $resourceName, bookDate: $bookDate, bookStartTime: $bookStartTime, bookEndTime: $bookEndTime, item_name: $item_name, is_cyclicity: $is_cyclicity, cyclicity_start_date: $cyclicity_start_date, cyclicity_end_date: $cyclicity_end_date, cyclicity_start_time: $cyclicity_start_time, cyclicity_end_time: $cyclicity_end_time, cyclicity_strategy: $cyclicity_strategy, cyclicity_weekList: $cyclicity_weekList, cyclicity_dayList: $cyclicity_dayList, order_by: $order_by, cur_language: $cur_language, filter: $filter) {\n    id\n    resources_type_id\n    resources_type_name\n    resources_number\n    resources_name\n    resources_name_en\n    open_captcha_verify\n    capacity_field_type\n    capacity\n    capacity_string\n    describe\n    describe_en\n    remark\n    created_user\n    created_user_name\n    state\n    can_location\n    campus_code\n    campus_name\n    campus_name_en\n    building_code\n    building_name\n    building_name_en\n    floor_code\n    floor_name\n    floor_name_en\n    qcode_image_url\n    order\n    admin_post\n    admin_post_name\n    admin_dept\n    admin_dept_name\n    rule_source\n    rule_template_id\n    appointment_open_date\n    appointment_close_date\n    appointment_open_time\n    appointment_close_time\n    appointment_date_rule\n    appointment_date_days\n    days_rule_effective_time\n    days_rule_refresh_time\n    advance_booking_rule\n    time_slot_rule\n    timeslot_latest_rule\n    timeslot_latest_deviation_minutes\n    min_interval_minutes\n    min_interval_minutes_prompt\n    min_interval_minutes_prompt_en\n    cyclicity_rule\n    batch_rule\n    is_notification_push\n    notifiy_channels\n    success_notification_push\n    success_notification_rule\n    cancel_notification_push\n    cancel_notification_rule_apply\n    cancel_notification_rule_admin\n    min_interval_minutes_change\n    min_interval_minutes_cancel\n    hide_appointment_information\n    appointment_information_field\n    hide_resources_detail\n    need_approve\n    open_process_form\n    success_prompt\n    success_prompt_en\n    del\n    create_time\n    resourcesMonthList {\n      id\n      resources_id\n      month\n      day\n      order_num\n      created_user_id\n      created_user_name\n      create_time\n    }\n    resourcesDate {\n      id\n      resources_id\n      start\n      end\n      order\n      del\n      create_time\n    }\n    resourcesWeek {\n      id\n      resources_id\n      zj\n      zj_name\n      order\n      del\n      create_time\n    }\n    resourcesTimeSlot {\n      id\n      resources_id\n      kssj\n      jssj\n      order\n      del\n      create_time\n    }\n    resourcesNoReservationConfigList {\n      id\n      resources_id\n      rule_type\n      month\n      day\n      start_date\n      end_date\n      week\n      start_time\n      end_time\n      reason_cn\n      reason_en\n      created_user_id\n      created_user_name\n      create_time\n    }\n    noReservationTimeSlotList {\n      book_date\n      start_time\n      end_time\n      reason_cn\n      reason_en\n    }\n    resourcesRoles {\n      id\n      resources_id\n      post\n      post_name\n      dept\n      dept_name\n      order\n      del\n      create_time\n    }\n    resourcesImage {\n      id\n      resources_id\n      uri\n      image_category\n      del\n      create_time\n    }\n    resourcesVisibleList {\n      id\n      resources_id\n      visible_obj_id\n      visible_obj_name\n      visible_obj_type\n      create_time\n    }\n    resourcesInvisibleList {\n      id\n      resources_id\n      invisible_obj_id\n      invisible_obj_name\n      invisible_obj_type\n      create_time\n    }\n    resourcesCooperativeDeptList {\n      id\n      resources_id\n      dept_id\n      dept_name\n      create_time\n    }\n    resourcesAuthList {\n      id\n      resources_id\n      resources_name\n      grant_open_id\n      grant_object_id\n      grant_object_name\n      grant_object_type\n      grant_permission_item\n      grant_time\n      operate_user_id\n      operate_user_name\n    }\n    available_number\n    per_max_available_number\n    resourcesExtendedPropertiesList {\n      id\n      resources_id\n      extended_properties_code\n      extended_properties_name\n      item_code\n      item_name\n      item_description\n      code_description\n    }\n    like\n    advance_booking\n    max_advance_booking_day\n    max_advance_booking_hour\n    max_advance_booking_minute\n    min_advance_booking_day\n    min_advance_booking_hour\n    min_advance_booking_minute\n    hits\n    review_url\n    resourcesConfig {\n      resources_id\n      separation_enable\n      preaudit_enable\n      preaudit_url\n      preaudit_description\n      preaudit_post\n      preaudit_dept\n      is_appointment_number_limit\n      appointment_number_rule\n      appointment_number_limit\n      timeperiod_number_begin_date\n      timeperiod_number_end_date\n      reservation_info_reuse\n      name_encryption_display\n      pertimeslot_min_minutes\n      pertimeslot_max_minutes\n      max_borrowing_days\n      max_waiting_days\n      return_need_approve\n      return_review_url\n      device_type\n      device_time_mode\n      signin_notification_push\n      signin_notification_rule\n      signin_rule\n      earliest_punctuality_rule\n      earliest_deviation_minutes\n      latest_punctuality_rule\n      latest_deviation_minutes\n      holding_minutes\n      sign_out_rule\n    }\n    resourcesCustomAttributeList {\n      id\n      resources_type_id\n      field_name\n      field_desc_cn\n      field_desc_en\n      field_desc_remark\n      collect_mode\n      default_value_cn\n      default_value_en\n      data_range_cn\n      data_range_en\n      is_required\n      is_detail_display\n      order_num\n    }\n    resourcesCustomAttributeContentList {\n      id\n      resources_id\n      field_name\n      field_desc_cn\n      field_desc_en\n      is_detail_display\n      attribute_content\n      is_enable\n      order_num\n    }\n    evaluateCount\n    average\n    totalSuccessReserveCounts\n    reservable_status\n    write_detail\n  }\n}\n'
            ),
            'variables': {
                'typeId': resource_type_id,
                'bookDate': self.config['book_date'],
                'bookStartTime': '',
                'bookEndTime': '',
                'item_name': [],
                'resourceName': '',
                'account': self.config['username'],
                'cur_language': 'zh',
                'order_by': '',
                'filter': {
                    'campus_code': {'eq': ''},
                    'building_code': {'eq': ''},
                    'floor_code': {'eq': ''},
                    'need_approve': {'eq': None}
                },
                'query': (
                    'query findResourcesAllByAccount($first: Int, $offset: Int, $typeId: String, $typeName: String, $resourceName: String, $bookDate: String, $bookStartTime: String, $bookEndTime: String, $item_name: [String], $is_cyclicity: String, $cyclicity_start_date: String, $cyclicity_end_date: String, $cyclicity_start_time: String, $cyclicity_end_time: String, $cyclicity_strategy: String, $cyclicity_weekList: [String], $cyclicity_dayList: [String], $order_by: String, $cur_language: String, $filter: ResourcesFilterMap) {\n  findResourcesAllByAccount(first: $first, offset: $offset, typeId: $typeId, typeName: $typeName, resourceName: $resourceName, bookDate: $bookDate, bookStartTime: $bookStartTime, bookEndTime: $bookEndTime, item_name: $item_name, is_cyclicity: $is_cyclicity, cyclicity_start_date: $cyclicity_start_date, cyclicity_end_date: $cyclicity_end_date, cyclicity_start_time: $cyclicity_start_time, cyclicity_end_time: $cyclicity_end_time, cyclicity_strategy: $cyclicity_strategy, cyclicity_weekList: $cyclicity_weekList, cyclicity_dayList: $cyclicity_dayList, order_by: $order_by, cur_language: $cur_language, filter: $filter) {\n    id\n    resources_type_id\n    resources_type_name\n    resources_number\n    resources_name\n    resources_name_en\n    open_captcha_verify\n    capacity_field_type\n    capacity\n    capacity_string\n    describe\n    describe_en\n    remark\n    created_user\n    created_user_name\n    state\n    can_location\n    campus_code\n    campus_name\n    campus_name_en\n    building_code\n    building_name\n    building_name_en\n    floor_code\n    floor_name\n    floor_name_en\n    qcode_image_url\n    order\n    admin_post\n    admin_post_name\n    admin_dept\n    admin_dept_name\n    rule_source\n    rule_template_id\n    appointment_open_date\n    appointment_close_date\n    appointment_open_time\n    appointment_close_time\n    appointment_date_rule\n    appointment_date_days\n    days_rule_effective_time\n    days_rule_refresh_time\n    advance_booking_rule\n    time_slot_rule\n    timeslot_latest_rule\n    timeslot_latest_deviation_minutes\n    min_interval_minutes\n    min_interval_minutes_prompt\n    min_interval_minutes_prompt_en\n    cyclicity_rule\n    batch_rule\n    is_notification_push\n    notifiy_channels\n    success_notification_push\n    success_notification_rule\n    cancel_notification_push\n    cancel_notification_rule_apply\n    cancel_notification_rule_admin\n    min_interval_minutes_change\n    min_interval_minutes_cancel\n    hide_appointment_information\n    appointment_information_field\n    hide_resources_detail\n    need_approve\n    open_process_form\n    success_prompt\n    success_prompt_en\n    del\n    create_time\n    resourcesMonthList {\n      id\n      resources_id\n      month\n      day\n      order_num\n      created_user_id\n      created_user_name\n      create_time\n    }\n    resourcesDate {\n      id\n      resources_id\n      start\n      end\n      order\n      del\n      create_time\n    }\n    resourcesWeek {\n      id\n      resources_id\n      zj\n      zj_name\n      order\n      del\n      create_time\n    }\n    resourcesTimeSlot {\n      id\n      resources_id\n      kssj\n      jssj\n      order\n      del\n      create_time\n    }\n    resourcesNoReservationConfigList {\n      id\n      resources_id\n      rule_type\n      month\n      day\n      start_date\n      end_date\n      week\n      start_time\n      end_time\n      reason_cn\n      reason_en\n      created_user_id\n      created_user_name\n      create_time\n    }\n    noReservationTimeSlotList {\n      book_date\n      start_time\n      end_time\n      reason_cn\n      reason_en\n    }\n    resourcesRoles {\n      id\n      resources_id\n      post\n      post_name\n      dept\n      dept_name\n      order\n      del\n      create_time\n    }\n    resourcesImage {\n      id\n      resources_id\n      uri\n      image_category\n      del\n      create_time\n    }\n    resourcesVisibleList {\n      id\n      resources_id\n      visible_obj_id\n      visible_obj_name\n      visible_obj_type\n      create_time\n    }\n    resourcesInvisibleList {\n      id\n      resources_id\n      invisible_obj_id\n      invisible_obj_name\n      invisible_obj_type\n      create_time\n    }\n    resourcesCooperativeDeptList {\n      id\n      resources_id\n      dept_id\n      dept_name\n      create_time\n    }\n    resourcesAuthList {\n      id\n      resources_id\n      resources_name\n      grant_open_id\n      grant_object_id\n      grant_object_name\n      grant_object_type\n      grant_permission_item\n      grant_time\n      operate_user_id\n      operate_user_name\n    }\n    available_number\n    per_max_available_number\n    resourcesExtendedPropertiesList {\n      id\n      resources_id\n      extended_properties_code\n      extended_properties_name\n      item_code\n      item_name\n      item_description\n      code_description\n    }\n    like\n    advance_booking\n    max_advance_booking_day\n    max_advance_booking_hour\n    max_advance_booking_minute\n    min_advance_booking_day\n    min_advance_booking_hour\n    min_advance_booking_minute\n    hits\n    review_url\n    resourcesConfig {\n      resources_id\n      separation_enable\n      preaudit_enable\n      preaudit_url\n      preaudit_description\n      preaudit_post\n      preaudit_dept\n      is_appointment_number_limit\n      appointment_number_rule\n      appointment_number_limit\n      timeperiod_number_begin_date\n      timeperiod_number_end_date\n      reservation_info_reuse\n      name_encryption_display\n      pertimeslot_min_minutes\n      pertimeslot_max_minutes\n      max_borrowing_days\n      max_waiting_days\n      return_need_approve\n      return_review_url\n      device_type\n      device_time_mode\n      signin_notification_push\n      signin_notification_rule\n      signin_rule\n      earliest_punctuality_rule\n      earliest_deviation_minutes\n      latest_punctuality_rule\n      latest_deviation_minutes\n      holding_minutes\n      sign_out_rule\n    }\n    resourcesCustomAttributeList {\n      id\n      resources_type_id\n      field_name\n      field_desc_cn\n      field_desc_en\n      field_desc_remark\n      collect_mode\n      default_value_cn\n      default_value_en\n      data_range_cn\n      data_range_en\n      is_required\n      is_detail_display\n      order_num\n    }\n    resourcesCustomAttributeContentList {\n      id\n      resources_id\n      field_name\n      field_desc_cn\n      field_desc_en\n      is_detail_display\n      attribute_content\n      is_enable\n      order_num\n    }\n    evaluateCount\n    average\n    totalSuccessReserveCounts\n    reservable_status\n    write_detail\n  }\n}\n'
                )
            }
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        
        respdata = json.loads(resp.text)
        resource_list = respdata['data']['findResourcesAllByAccount']
        infostr = ''
        for res in resource_list:
            infostr += '\n%s %s' % (res['resources_name'],res['id'])
        _logprint('Query resources for [%s] %s:%s' %
                  (resource_name, self.config['book_date'], infostr))
    
    def queryShowTimeslotList(self, id: str):
        resource_data = self._getResourceData(id)
        inforstr = ''
        timeslot_list = resource_data['resourcesTimeSlot']
        for timeslot in timeslot_list:
            inforstr += '\n%s-%s %s' % (
                timeslot['kssj'],
                timeslot['jssj'],
                timeslot['id']
            )
        _logprint('Query timeslots for [%s] %s:%s' %(
            resource_data['resources_name'],
            self.config['book_date'],
            inforstr
        ))

    def _getResourceData(self, id: str) -> dict:
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'findResources',
            'query': (
                'query findResources($id: ID!, $filter: ResourcesFilterMap) {\n  findResources(id: $id, filter: $filter) {\n    id\n    resources_type_id\n    resources_number\n    resources_name\n    resources_name_en\n    open_captcha_verify\n    capacity_field_type\n    capacity\n    capacity_string\n    describe\n    describe_en\n    remark\n    created_user\n    created_user_name\n    state\n    average\n    can_location\n    campus_code\n    campus_name\n    campus_name_en\n    building_code\n    building_name\n    building_name_en\n    floor_code\n    floor_name\n    floor_name_en\n    qcode_image_url\n    order\n    admin_post\n    admin_post_name\n    admin_dept\n    admin_dept_name\n    rule_source\n    rule_template_id\n    appointment_open_date\n    appointment_close_date\n    appointment_open_time\n    appointment_close_time\n    appointment_date_rule\n    appointment_date_days\n    days_rule_effective_time\n    days_rule_refresh_time\n    advance_booking_rule\n    time_slot_rule\n    timeslot_latest_rule\n    timeslot_latest_deviation_minutes\n    min_interval_minutes\n    min_interval_minutes_prompt\n    min_interval_minutes_prompt_en\n    cyclicity_rule\n    batch_rule\n    is_notification_push\n    notifiy_channels\n    success_notification_push\n    success_notification_rule\n    cancel_notification_push\n    cancel_notification_rule_apply\n    cancel_notification_rule_admin\n    min_interval_minutes_change\n    min_interval_minutes_cancel\n    hide_appointment_information\n    appointment_information_field\n    need_approve\n    open_process_form\n    success_prompt\n    success_prompt_en\n    del\n    create_time\n    resourcesMonthList {\n      id\n      resources_id\n      month\n      day\n      order_num\n      created_user_id\n      created_user_name\n      create_time\n    }\n    resourcesDate {\n      id\n      resources_id\n      start\n      end\n      order\n      del\n      create_time\n    }\n    resourcesWeek {\n      id\n      resources_id\n      zj\n      zj_name\n      order\n      del\n      create_time\n    }\n    resourcesTimeSlot {\n      id\n      resources_id\n      kssj\n      jssj\n      order\n      del\n      create_time\n    }\n    resourcesNoReservationConfigList {\n      id\n      resources_id\n      rule_type\n      month\n      day\n      start_date\n      end_date\n      week\n      start_time\n      end_time\n      reason_cn\n      reason_en\n      created_user_id\n      created_user_name\n      create_time\n    }\n    resourcesRoles {\n      id\n      resources_id\n      post\n      post_name\n      dept\n      dept_name\n      order\n      del\n      create_time\n    }\n    resourcesImage {\n      id\n      resources_id\n      uri\n      image_category\n      del\n      create_time\n    }\n    resourcesVisibleList {\n      id\n      resources_id\n      visible_obj_id\n      visible_obj_name\n      visible_obj_type\n      create_time\n    }\n    resourcesInvisibleList {\n      id\n      resources_id\n      invisible_obj_id\n      invisible_obj_name\n      invisible_obj_type\n      create_time\n    }\n    resourcesCooperativeDeptList {\n      id\n      resources_id\n      dept_id\n      dept_name\n      create_time\n    }\n    resourcesAuthList {\n      id\n      resources_id\n      resources_name\n      grant_open_id\n      grant_object_id\n      grant_object_name\n      grant_object_type\n      grant_permission_item\n      grant_time\n      operate_user_id\n      operate_user_name\n    }\n    available_number\n    per_max_available_number\n    resourcesExtendedPropertiesList {\n      id\n      resources_id\n      extended_properties_code\n      extended_properties_name\n      item_code\n      item_name\n      item_description\n      code_description\n    }\n    advance_booking\n    max_advance_booking_day\n    max_advance_booking_hour\n    max_advance_booking_minute\n    min_advance_booking_day\n    min_advance_booking_hour\n    min_advance_booking_minute\n    review_url\n    resourcesConfig {\n      resources_id\n      separation_enable\n      preaudit_enable\n      preaudit_url\n      preaudit_description\n      preaudit_post\n      preaudit_dept\n      is_appointment_number_limit\n      appointment_number_rule\n      appointment_number_limit\n      timeperiod_number_begin_date\n      timeperiod_number_end_date\n      reservation_info_reuse\n      name_encryption_display\n      pertimeslot_min_minutes\n      pertimeslot_max_minutes\n      max_borrowing_days\n      max_waiting_days\n      return_need_approve\n      return_review_url\n      device_type\n      device_time_mode\n      signin_notification_push\n      signin_notification_rule\n      signin_rule\n      earliest_punctuality_rule\n      earliest_deviation_minutes\n      latest_punctuality_rule\n      latest_deviation_minutes\n      holding_minutes\n      sign_out_rule\n    }\n    resourcesCustomAttributeList {\n      id\n      resources_type_id\n      field_name\n      field_desc_cn\n      field_desc_en\n      field_desc_remark\n      collect_mode\n      default_value_cn\n      default_value_en\n      data_range_cn\n      data_range_en\n      is_required\n      is_detail_display\n      order_num\n    }\n    resourcesCustomAttributeContentList {\n      id\n      resources_id\n      field_name\n      field_desc_cn\n      field_desc_en\n      is_detail_display\n      attribute_content\n      is_enable\n      order_num\n    }\n    resourcesAvailableNumberRuleList {\n      resources_id\n      time_slot_rule\n      date_rule\n      start_date\n      end_date\n      weeks\n      start_time\n      end_time\n      available_number\n    }\n    resourcesAppointmentNumberLimitRuleList {\n      id\n      resources_id\n      appointment_number_rule\n      appointment_number_limit\n      timeperiod_number_begin_date\n      timeperiod_number_end_date\n      tenant_id\n    }\n    userDisplayInfoConfigList {\n      id\n      resource_type_id\n      field_name_en\n      field_name_cn\n      field_data_type\n      field_category\n      display_order_num\n      tenant_id\n    }\n    write_detail\n    wemeet_enable\n  }\n}\n'
            ),
            'variables': {'id': id}
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        return json.loads(resp.text)['data']['findResources']

    def _generateTargetQueryList(self) -> list:
        target_list = self.config['target_list']
        # id = self.config['target_list'][0]['resource_id']
        query_list = []
        
        for instance in target_list:
            inst_data = self._getResourceData(instance['resource_id'])
            inst_name = inst_data['resources_name']
            timeslot_list = inst_data['resourcesTimeSlot']
            timeslot = next(filter(
                lambda slot: slot['id'] == instance['resource_timeslot_id'],
                timeslot_list
            ), None)
            query_variables = {
                'resourceId': instance['resource_id'],
                'bookDate': self.config['book_date'],
                'bookStartTime': timeslot['kssj'],
                'bookEndTime': timeslot['jssj'],
                'timeSlotIdList': [timeslot['id']],
                'resourceName': inst_name
            }
            query_list.append(query_variables)
        return query_list
    
    def _isTargetAvailable(self, target: dict) -> bool:
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'checkResourceTimeSlotCapacity',
            'query': (
                'query checkResourceTimeSlotCapacity($resourceId: String, $appointmentId: String, $bookDate: String, $bookStartTime: String, $bookEndTime: String, $timeSlotIdList: [String], $borrowDateList: [String], $borrowStartTime: String, $borrowEndTime: String, $checkSource: String) {\n  checkResourceTimeSlotCapacity(resourceId: $resourceId, appointmentId: $appointmentId, bookDate: $bookDate, bookStartTime: $bookStartTime, bookEndTime: $bookEndTime, timeSlotIdList: $timeSlotIdList, borrowDateList: $borrowDateList, borrowStartTime: $borrowStartTime, borrowEndTime: $borrowEndTime, checkSource: $checkSource) {\n    code\n    name\n    messages\n    messages_en\n  }\n}\n'
            ),
            'variables': {
                'resourceId': target['resourceId'],
                'bookDate': target['bookDate'],
                'bookStartTime': target['bookStartTime'],
                'bookEndTime': target['bookEndTime'],
                'timeSlotIdList': target['timeSlotIdList']
            }
            
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        respdata = json.loads(resp.text)

        return respdata['data']['checkResourceTimeSlotCapacity']['code'] == '0'

    def _timeTo1230pm(self) -> float:
        now = datetime.datetime.now()
        target_time = now.replace(hour=12, minute=30, second=0, microsecond=0)
        if now > target_time:
            target_time += datetime.timedelta(days=1)
        delta = (target_time - now).total_seconds()
        return delta

    def sleepTo1230pm(self):
        _logprint('Sleeping to 12:30 PM...')
        delta = self._timeTo1230pm()
        
        # 如果距离目标时间太近（小于30秒），直接跳过刷新登录
        if delta <= 30:
            _logprint('Too close to target time (%.2f seconds), skipping login refresh.' % delta)
            if delta > 0:
                time.sleep(delta)
            return
        
        while delta > 30:  # 30秒刷新时间
            time.sleep(10)
            delta = self._timeTo1230pm()
        
        _logprint('Trigger in bound in %s seconds.' % delta)
        
        # 记录刷新前的剩余时间
        refresh_start_time = datetime.datetime.now()
        remaining_time_before_refresh = self._timeTo1230pm()
        
        _logprint('Refreshing login status...')
        self.login()
        self.auth()
        self.captcha_killer.updateKey(self.bearer_tk)
        
        # 计算刷新登录消耗的时间
        refresh_duration = (datetime.datetime.now() - refresh_start_time).total_seconds()
        _logprint('Login refresh took %.2f seconds.' % refresh_duration)
        
        # 重新计算剩余时间
        final_delta = self._timeTo1230pm()
        
        # 如果已经过了目标时间，说明刷新登录耗时太长
        if final_delta > 86000:  # 大于24小时-400秒，说明已经过了今天的12:30
            _logprint('Warning: Missed target time due to login refresh delay!')
            return
        
        # 如果还有剩余时间，继续等待
        if final_delta > 0:
            _logprint('Final wait: %.3f seconds.' % final_delta)
            time.sleep(final_delta)

    def reviewTarget(self):
        infostr = ''
        target_query_list = self._generateTargetQueryList()
        for target in target_query_list:
            infostr += ('\n%s-%s %s' % (
                target['bookStartTime'],
                target['bookEndTime'],
                target['resourceName']
            ))
        _logprint('Config target list query success!\n--%s--%s' %
                  (self.config['book_date'], infostr))

    def rsvResource(self, target: dict, captcha_payload: dict) -> dict:
        infolog = '--%s-- %s-%s %s\n' % (
            self.config['book_date'],
            target['bookStartTime'],
            target['bookEndTime'],
            target['resourceName']
        )
        bookdate_unix = int(time.mktime(
                            datetime.datetime.strptime(
                                self.config['book_date'], "%Y-%m-%d"
                            ).timetuple()
                        )) * 1000
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'saveAppointmentInformationAll',
            'variables': {
                'captchaId': captcha_payload['captchaId'],
                'captchaCode': captcha_payload['captchaCode'],
                'timeSlotIdList': target['timeSlotIdList'],
                'model': {
                    'created_user': self.userinfo['account'],
                    'created_user_name': self.userinfo['name'],
                    'appointment_user': self.userinfo['account'],
                    'appointment_user_name': self.userinfo['name'],
                    'state': 0,
                    'resources_id': target['resourceId'],
                    'dept_code': self.userinfo['positions'][0]['dept']['code'],
                    'dept_name': self.userinfo['positions'][0]['dept']['name'],
                    'dept_name_en': '',
                    'email': None,
                    'phone': self.userinfo['phone'],
                    'person_times': 1,
                    'wemeet_enable': 0,
                    'theme': '',
                    'enclosure': '',
                    'participants_scope': '',
                    'remark': '',
                    'event': '',
                    'appointmentParticipantList': [{
                        'participant_dept_id': (self.userinfo['positions'][0]
                                                ['dept']['id']),
                        'participant_dept_name': (self.userinfo['positions'][0]
                                                  ['dept']['name']),
                        'participant_id': self.userinfo['account'],
                        'participant_name': self.userinfo['name'],
                        'mobile': self.userinfo['phone'],
                        'email': None,
                        'operate_user_id': self.userinfo['account'],
                        'operate_user_name': self.userinfo['name'],
                    }],
                    'appointment_date': bookdate_unix,
                    'start_time': target['bookStartTime'],
                    'end_time': target['bookEndTime'],
                },
            },
            'query': (
                'mutation saveAppointmentInformationAll($captchaId: String, $captchaCode: String, $model: InputAppointmentInformation!, $timeSlotIdList: [String], $borrowDateList: [String], $borrowStartTime: String, $borrowEndTime: String) {\n  saveAppointmentInformationAll(captchaId: $captchaId, captchaCode: $captchaCode, model: $model, timeSlotIdList: $timeSlotIdList, borrowDateList: $borrowDateList, borrowStartTime: $borrowStartTime, borrowEndTime: $borrowEndTime) {\n    code\n    name\n    messages\n    messages_en\n    ids\n    appointmentId\n    processURL\n    auditStatus\n  }\n}\n'
            )
        }
        resp = self.sess.post(self._url_gym_sysquery,
                              params=query,
                              data=json.dumps(payload))
        respdata = (json.loads(resp.text)['data']
                    ['saveAppointmentInformationAll'])
        infolog += str(respdata)
        _logprint('Reservation:\n%s'% infolog)
        return respdata

    def autoRsv(self): 
        target_query_list = self._generateTargetQueryList()
        for target in target_query_list:
            if not self._isTargetAvailable(target):
                _logprint('Skipping unavailable target:\n--%s-- %s-%s %s' % (
                    self.config['book_date'],
                    target['bookStartTime'],
                    target['bookEndTime'],
                    target['resourceName']
                ))
            else:
                captcha_resp = {}
                while captcha_resp == {}:
                    captcha_resp = self.captcha_killer.solveCaptcha()
                rsv_info = self.rsvResource(target, captcha_resp)
                if rsv_info['code'] == '0':
                    _logprint('Reservation success!')
                    break
    

    def updateConfig(self):
        """
        交互式更新配置文件的功能
        """
        _logprint('Starting interactive config update...')
        
        # 1. 更新预订日期
        print("\n=== Update Book Date ===")
        current_date = self.config.get('book_date', '')
        print(f"Current book date: {current_date}")
        new_date = input("Enter new book date (YYYY-MM-DD) or press Enter to keep current: ").strip()
        
        if new_date:
            # 验证日期格式
            try:
                datetime.datetime.strptime(new_date, "%Y-%m-%d")
                self.config['book_date'] = new_date
                self._saveConfig()
                _logprint(f'Updated book_date to: {new_date}')
            except ValueError:
                _logerrorExit('Invalid date format. Please use YYYY-MM-DD format.')
        
        # 2. 查询并选择资源
        print("\n=== Select Resources ===")
        print("Querying available badminton courts...")
        
        # 获取羽毛球场资源列表
        resource_type_id = self._getResourceTypeId('羽毛球场')
        query = {'id_token_hint': self.id_tk}
        payload = {
            'operationName': 'findResourcesAllByAccount',
            'query': (
                'query findResourcesAllByAccount($first: Int, $offset: Int, $typeId: String, $typeName: String, $resourceName: String, $bookDate: String, $bookStartTime: String, $bookEndTime: String, $item_name: [String], $is_cyclicity: String, $cyclicity_start_date: String, $cyclicity_end_date: String, $cyclicity_start_time: String, $cyclicity_end_time: String, $cyclicity_strategy: String, $cyclicity_weekList: [String], $cyclicity_dayList: [String], $order_by: String, $cur_language: String, $filter: ResourcesFilterMap) {\n  findResourcesAllByAccount(first: $first, offset: $offset, typeId: $typeId, typeName: $typeName, resourceName: $resourceName, bookDate: $bookDate, bookStartTime: $bookStartTime, bookEndTime: $bookEndTime, item_name: $item_name, is_cyclicity: $is_cyclicity, cyclicity_start_date: $cyclicity_start_date, cyclicity_end_date: $cyclicity_end_date, cyclicity_start_time: $cyclicity_start_time, cyclicity_end_time: $cyclicity_end_time, cyclicity_strategy: $cyclicity_strategy, cyclicity_weekList: $cyclicity_weekList, cyclicity_dayList: $cyclicity_dayList, order_by: $order_by, cur_language: $cur_language, filter: $filter) {\n    id\n    resources_name\n    campus_name\n    building_name\n    floor_name\n    capacity\n    describe\n    available_number\n  }\n}\n'
            ),
            'variables': {
                'typeId': resource_type_id,
                'bookDate': self.config['book_date'],
                'bookStartTime': '',
                'bookEndTime': '',
                'item_name': [],
                'resourceName': '',
                'account': self.config['username'],
                'cur_language': 'zh',
                'order_by': '',
                'filter': {
                    'campus_code': {'eq': ''},
                    'building_code': {'eq': ''},
                    'floor_code': {'eq': ''},
                    'need_approve': {'eq': None}
                }
            }
        }
        
        resp = self.sess.post(self._url_gym_sysquery, params=query, data=json.dumps(payload))
        respdata = json.loads(resp.text)
        resource_list = respdata['data']['findResourcesAllByAccount']
        
        # 显示可用资源
        print("\nAvailable badminton courts:")
        for i, res in enumerate(resource_list):
            print(f"[{i+1}] {res['resources_name']} (ID: {res['id']})")
            print(f"    Location: {res.get('campus_name', '')} {res.get('building_name', '')} {res.get('floor_name', '')}")
            print(f"    Capacity: {res.get('capacity', 'N/A')}")
            if res.get('describe'):
                print(f"    Description: {res['describe']}")
            print()
        
        # 选择资源并更新配置
        new_target_list = []
        
        while True:
            try:
                choice = input("Select a court by number (or 'done' to finish, 'skip' to keep current targets): ").strip()
                
                if choice.lower() == 'done':
                    break
                elif choice.lower() == 'skip':
                    _logprint('Keeping current target list unchanged.')
                    return
                
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(resource_list):
                    selected_resource = resource_list[choice_idx]
                    resource_id = selected_resource['id']
                    resource_name = selected_resource['resources_name']
                    
                    print(f"\nSelected: {resource_name}")
                    print("Querying available time slots...")
                    
                    # 获取时间段列表
                    resource_data = self._getResourceData(resource_id)
                    timeslot_list = resource_data['resourcesTimeSlot']
                    
                    if not timeslot_list:
                        print("No time slots available for this resource.")
                        continue
                    
                    print("\nAvailable time slots:")
                    for i, timeslot in enumerate(timeslot_list):
                        print(f"[{i+1}] {timeslot['kssj']}-{timeslot['jssj']} (ID: {timeslot['id']})")
                    
                    # 选择时间段
                    while True:
                        try:
                            slot_choice = input("Select a time slot by number: ").strip()
                            slot_idx = int(slot_choice) - 1
                            
                            if 0 <= slot_idx < len(timeslot_list):
                                selected_timeslot = timeslot_list[slot_idx]
                                timeslot_id = selected_timeslot['id']
                                timeslot_time = f"{selected_timeslot['kssj']}-{selected_timeslot['jssj']}"
                                
                                # 添加到目标列表
                                target_entry = {
                                    "resource_id": resource_id,
                                    "resource_timeslot_id": timeslot_id
                                }
                                new_target_list.append(target_entry)
                                
                                _logprint(f'Added target: {resource_name} {timeslot_time}')
                                print(f"Added: {resource_name} {timeslot_time}")
                                break
                            else:
                                print("Invalid selection. Please try again.")
                        except ValueError:
                            print("Please enter a valid number.")
                    
                else:
                    print("Invalid selection. Please try again.")
                    
            except ValueError:
                print("Please enter a valid number or 'done'/'skip'.")
        
        # 更新配置文件
        if new_target_list:
            self.config['target_list'] = new_target_list
            self._saveConfig()
            _logprint(f'Updated target_list with {len(new_target_list)} targets.')
            
            # 显示更新后的配置
            print("\n=== Updated Configuration ===")
            print(f"Book Date: {self.config['book_date']}")
            print("Target List:")
            for i, target in enumerate(new_target_list):
                resource_data = self._getResourceData(target['resource_id'])
                timeslot = next(filter(
                    lambda slot: slot['id'] == target['resource_timeslot_id'],
                    resource_data['resourcesTimeSlot']
                ), None)
                if timeslot:
                    print(f"  [{i+1}] {resource_data['resources_name']} {timeslot['kssj']}-{timeslot['jssj']}")
        else:
            _logprint('No targets were added.')

    def _saveConfig(self):
        """
        保存配置到文件
        """
        with open(self._path_config, 'w', encoding='utf-8') as config_file:
            json.dump(self.config, config_file, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    helper = SEUGymRsvHelper()

    # 添加交互式配置更新选项
    print("\n=== SEU Gym Reservation Helper ===")
    print("1. Update configuration interactively")
    print("2. Run reservation with current config")
    print("3. Query resources and timeslots only")
    
    choice = input("Select an option (1-3): ").strip()
    
    if choice == '1':
        helper.updateConfig()
        print("\nConfiguration updated! You can now run the reservation or exit.")
        run_reservation = input("Do you want to run reservation now? (y/n): ").strip().lower()
        if run_reservation == 'y':
            helper.sleepTo1230pm()
            helper.reviewTarget()
            helper.autoRsv()
    elif choice == '2':
        helper.sleepTo1230pm()
        helper.reviewTarget()
        helper.autoRsv()
    elif choice == '3':
        helper.queryShowResourceList('羽毛球场')
        if helper.config['target_list']:
            first_resource_id = helper.config['target_list'][0]['resource_id']
            helper.queryShowTimeslotList(first_resource_id)
    else:
        print("Invalid choice. Exiting...")

    # I am getting tired of all these query stuff,
    # so whatever, get those IDs yourself!!!
    # # 提取并打印config.json中的元素
    # print("=== Config Information ===")
    # print(f"Username: {helper.config['username']}")
    # print(f"Book Date: {helper.config['book_date']}")
    
    # # 提取target_list中的resource_id
    # print("\n=== Target Resource IDs ===")
    # for i, target in enumerate(helper.config['target_list']):
    #     print(f"Target [{i+1}]:")
    #     print(f"  Resource ID: {target['resource_id']}")
    #     print(f"  Timeslot ID: {target['resource_timeslot_id']}")
    
    # # 使用第一个target的resource_id进行查询
    # first_resource_id = helper.config['target_list'][0]['resource_id']
    # print(f"\nUsing first resource ID: {first_resource_id}")

    # helper.queryShowResourceList('羽毛球场')
    # helper.queryShowTimeslotList(first_resource_id)
    # exit()

    
