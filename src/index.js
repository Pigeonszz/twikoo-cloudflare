import { WorkerEntrypoint } from "cloudflare:workers";
import { v4 as uuidv4 } from 'uuid';
import xss from 'xss';
import {
  getCheerio,
  getMd5,
  getSha256,
  getXml2js,
  setCustomLibs
} from 'twikoo-func/utils/lib';
import {
  getFuncVersion,
  parseComment,
  normalizeMail,
  equalsMail,
  getMailMd5,
  getAvatar,
  isQQ,
  addQQMailSuffix,
  getQQAvatar,
  getPasswordStatus,
  preCheckSpam,
  getConfig,
  getConfigForAdmin,
  validate
} from 'twikoo-func/utils';
import {
  jsonParse,
  commentImportValine,
  commentImportDisqus,
  commentImportArtalk,
  commentImportArtalk2,
  commentImportTwikoo
} from 'twikoo-func/utils/import';
import { postCheckSpam } from 'twikoo-func/utils/spam';
import { sendNotice, emailTest } from 'twikoo-func/utils/notify';
import { uploadImage } from 'twikoo-func/utils/image';
import logger from 'twikoo-func/utils/logger';

// 常量 / constants
import constants from 'twikoo-func/utils/constants';

// 注入Cloudflare特定的依赖
setCustomLibs({
  DOMPurify: {
    sanitize (input) {
      return input
    }
  },

  nodemailer: {
    createTransport (config) {
      return {
        verify () {
          if (!config.service || (config.service.toLowerCase() !== 'sendgrid' && config.service.toLowerCase() !== 'mailchannels')) {
            throw new Error('仅支持 SendGrid 和 MailChannels 邮件服务。');
          }
          if (!config.auth || !config.auth.user) {
            throw new Error('需要在 SMTP_USER 中配置账户名，如果邮件服务不需要可随意填写。');
          }
          if (!config.auth || !config.auth.pass) {
            throw new Error('需要在 SMTP_PASS 中配置 API 令牌。');
          }
          return true
        },

        sendMail ({ from, to, subject, html }) {
          if (config.service.toLowerCase() === 'sendgrid') {
            return fetch('https://api.sendgrid.com/v3/mail/send', {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${config.auth.pass}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: from },
                subject,
                content: [{ type: 'text/html', value: html }],
              })
            })
          } else if (config.service.toLowerCase() === 'mailchannels') {
            return fetch('https://api.mailchannels.net/tx/v1/send', {
              method: 'POST',
              headers: {
                'X-Api-Key': config.auth.pass,
                'Accept': 'application/json',
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: from },
                subject,
                content: [{ type: 'text/html', value: html }],
              })
            })
          }
        }
      }
    }
  }
})

const $ = getCheerio();
const md5 = getMd5();
const sha256 = getSha256();
const xml2js = getXml2js();

const { RES_CODE, MAX_REQUEST_TIMES } = constants;
const VERSION = '1.6.44';

class DBBinding {
  constructor (binding) {
    this.DB = binding
  }

  get commentCountQuery () {
    return this._commentCountQuery ?? (this._commentCountQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE url = ?1 AND rid = "" AND (isSpam != ?2 OR uid = ?3)
`.trim()))
  }

  get commentQuery () {
    return this._commentQuery ?? (this._commentQuery = this.DB.prepare(`
SELECT * FROM comment
WHERE
  url = ?1 AND
  (isSpam != ?2 OR uid = ?3) AND
  created < ?4 AND
  top = ?5 AND
  rid = ""
ORDER BY created DESC
LIMIT ?6
`.trim()))
  }

  static replyQueryTemplate = `
SELECT * FROM comment
WHERE
  url = ?1 AND
  (isSpam != ?2 OR uid = ?3) AND
  rid IN ({{RIDS}})
`.trim()

  getReplyQuery (numParams) {
    if (!this.replyQueryCache) this.replyQueryCache = new Map()
    const cached = this.replyQueryCache.get(numParams)
    if (cached) return cached
    const result = this.DB.prepare(DBBinding.replyQueryTemplate.replace(
      '{{RIDS}}',	new Array(numParams).fill('?').join(', ')))
    this.replyQueryCache.set(numParams, result)
    return result
  }

  get commentForAdminCountQuery () {
    return this._commentForAdminCountQuery ?? (this._commentForAdminCountQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE
  isSpam != ?1 AND
  (nick LIKE ?2 OR
  mail LIKE ?2 OR
  link LIKE ?2 OR
  ip LIKE ?2 OR
  comment LIKE ?2 OR
  url LIKE ?2 OR
  href LIKE ?2)
`.trim()))
  }

  get commentForAdminQuery () {
    return this._commentForAdminQuery ?? (this._commentForAdminQuery = this.DB.prepare(`
SELECT * FROM comment
WHERE
  isSpam != ?1 AND
  (nick LIKE ?2 OR
  mail LIKE ?2 OR
  link LIKE ?2 OR
  ip LIKE ?2 OR
  comment LIKE ?2 OR
  url LIKE ?2 OR
  href LIKE ?2)
  ORDER BY created DESC
  LIMIT ?3 OFFSET ?4
`.trim()))
  }

  static commentSetStmtTemplate = `
UPDATE comment
SET {{FIELDS}}
WHERE _id = ?
`.trim()

  getCommentSetStmt (fields) {
    if (!this.commentSetStmtCache) this.commentSetStmtCache = new Map()
    const cacheKey = JSON.stringify(fields)
    const cached = this.commentSetStmtCache.get(cacheKey)
    if (cached) return cached
    const result = this.DB.prepare(DBBinding.commentSetStmtTemplate.replace(
      '{{FIELDS}}', fields.map(field => `${field} = ?`).join(', ')
    ))
    this.commentSetStmtCache.set(cacheKey, result)
    return result
  }

  get commentDeleteStmt () {
    return this._commentDeleteStmt ?? (this._commentDeleteStmt =
      this.DB.prepare('DELETE FROM comment WHERE _id = ?1')
    )
  }

  get commentExportQuery () {
    return this._commentExportQuery ?? (this._commentExportQuery =
      this.DB.prepare('SELECT * FROM comment')
    )
  }

  get commentByIdQuery () {
    return this._commentByIdQuery ?? (this._commentByIdQuery =
      this.DB.prepare('SELECT * FROM comment WHERE _id = ?1')
    )
  }

  get updateLikeStmt () {
    return this._updateLikeStmt ?? (this._updateLikeStmt =
      this.DB.prepare('UPDATE comment SET like = ?2 WHERE _id = ?1')
    )
  }

  get saveCommentStmt () {
    return this._saveCommentStmt ?? (this._saveCommentStmt =
      this.DB.prepare(`
INSERT INTO comment VALUES (
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
  ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
)
`.trim()))
  }

  get commentCountSinceByIpQuery () {
    return this._commentCountSinceByIpQuery ?? (this._commentCountSinceByIpQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE created > ?1 AND ip = ?2
`.trim()))
  }

  get commentCountSinceQuery () {
    return this._commentCountSinceQuery ?? (this._commentCountSinceQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE created > ?1
`.trim()))
  }

  get updateIsSpamStmt () {
    return this._updateIsSpamStmt ?? (this._updateIsSpamStmt = this.DB.prepare(`
UPDATE comment SET isSpam = ?2, updated = ?3 WHERE _id = ?1
`.trim()))
  }

  get incCounterStmt () {
    return this._incCounterStmt ?? (this._incCounterStmt = this.DB.prepare(`
INSERT INTO counter VALUES
(?1, ?2, 1, ?3, ?3)
ON CONFLICT (url) DO UPDATE SET time = time + 1, title = ?2, updated = ?3
`.trim()))
  }

  get counterQuery () {
    return this._counterQuery ?? (this._counterQuery =
      this.DB.prepare('SELECT time FROM counter WHERE url = ?1')
    )
  }

  get commentCountByUrlQuery () {
    return this._commentCountByUrlQuery ?? (this._commentCountByUrlQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE url = ?1 AND NOT isSpam AND (?2 OR rid = "")
`.trim()))
  }

  get recentCommentsByUrlQuery () {
    return this._recentCommentsByUrlQuery ?? (this._recentCommentsByUrlQuery = this.DB.prepare(`
SELECT * FROM comment
WHERE
  (?1 OR url = ?2) AND
  NOT isSpam AND
  (?3 OR rid = "") AND
LIMIT ?4
`.trim()))
  }

  get readConfigQuery () {
    return this._readConfigQuery ?? (this._readConfigQuery =
      this.DB.prepare('SELECT value FROM config LIMIT 1')
    )
  }

  get writeConfigStmt () {
    return this._writeConfigStmt ?? (this._writeConfigStmt =
      this.DB.prepare('UPDATE config SET value = ?1')
    )
  }
}

// Twikoo 主服务 - 作为 Service Binding
export default class TwikooService extends WorkerEntrypoint {
  constructor(ctx, env) {
    super(ctx, env);
    this.db = new DBBinding(env.DB);
    this.config = {};
    this.accessToken = '';
    this.requestTimes = {};
  }

  // 必须的 fetch 方法
  async fetch(request) {
    const url = new URL(request.url);

    // 只处理 /api/v1/twikoo 路径的请求
    if (url.pathname === '/api/v1/twikoo') {
      return await this.handleTwikooRequest(request);
    }

    return new Response(null, { status: 404 });
  }

  // 处理 Twikoo 请求的核心逻辑
  async handleTwikooRequest(request) {
    let event;
    try {
      if (request.method === 'POST') {
        event = await request.json();
      } else {
        event = {};
      }
    } catch {
      event = {};
    }

    logger.log('Twikoo Service - 请求 IP：', this.getIp(request));
    logger.log('Twikoo Service - 请求函数：', event.event);
    logger.log('Twikoo Service - 请求参数：', event);

    let res = {};
    const headers = {};

    try {
      this.protect(request);
      this.accessToken = this.anonymousSignIn(event);
      await this.readConfig();
      this.allowCors(request, headers);

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers });
      }

      // 处理各种 Twikoo 事件
      switch (event.event) {
        case 'GET_FUNC_VERSION':
          res = getFuncVersion({ VERSION });
          break;
        case 'COMMENT_GET':
          res = await this.commentGet(event);
          break;
        case 'COMMENT_GET_FOR_ADMIN':
          res = await this.commentGetForAdmin(event);
          break;
        case 'COMMENT_SET_FOR_ADMIN':
          res = await this.commentSetForAdmin(event);
          break;
        case 'COMMENT_DELETE_FOR_ADMIN':
          res = await this.commentDeleteForAdmin(event);
          break;
        case 'COMMENT_IMPORT_FOR_ADMIN':
          res = await this.commentImportForAdmin(event);
          break;
        case 'COMMENT_LIKE':
          res = await this.commentLike(event);
          break;
        case 'COMMENT_SUBMIT':
          res = await this.commentSubmit(event, request);
          break;
        case 'COUNTER_GET':
          res = await this.counterGet(event);
          break;
        case 'GET_PASSWORD_STATUS':
          res = await getPasswordStatus(this.config, VERSION);
          break;
        case 'SET_PASSWORD':
          res = await this.setPassword(event);
          break;
        case 'GET_CONFIG':
          res = await getConfig({ config: this.config, VERSION, isAdmin: this.isAdmin() });
          break;
        case 'GET_CONFIG_FOR_ADMIN':
          res = await getConfigForAdmin({ config: this.config, isAdmin: this.isAdmin() });
          break;
        case 'SET_CONFIG':
          res = await this.setConfig(event);
          break;
        case 'LOGIN':
          res = await this.login(event.password);
          break;
        case 'GET_COMMENTS_COUNT':
          res = await this.getCommentsCount(event);
          break;
        case 'GET_RECENT_COMMENTS':
          res = await this.getRecentComments(event);
          break;
        case 'EMAIL_TEST':
          res = await emailTest(event, this.config, this.isAdmin());
          break;
        case 'UPLOAD_IMAGE':
          if (this.env.R2 && this.env.R2_PUBLIC_URL) {
            res = await this.r2_upload(event, this.env.R2, this.env.R2_PUBLIC_URL);
          } else {
            res = await uploadImage(event, this.config);
          }
          break;
        case 'COMMENT_EXPORT_FOR_ADMIN':
          res = await this.commentExportForAdmin(event);
          break;
        default:
          if (event.event) {
            res.code = RES_CODE.EVENT_NOT_EXIST;
            res.message = '请更新 Twikoo 云函数至最新版本';
          } else {
            res.code = RES_CODE.NO_PARAM;
            res.message = 'Twikoo 云函数运行正常，请参考 https://twikoo.js.org/frontend.html 完成前端的配置';
            res.version = VERSION;
          }
      }
    } catch (e) {
      logger.error('Twikoo Service - 遇到错误，请参考以下错误信息。如有疑问，请反馈至 https://github.com/twikoojs/twikoo/issues');
      logger.error('Twikoo Service - 请求参数：', event);
      logger.error('Twikoo Service - 错误信息：', e);
      res.code = RES_CODE.FAIL;
      res.message = e.message;
    }

    if (!res.code && !event.accessToken) {
      res.accessToken = this.accessToken;
    }

    logger.log('Twikoo Service - 请求返回：', res);
    headers['content-type'] = 'application/json;charset=UTF-8';
    return new Response(JSON.stringify(res), { headers });
  }

  // 辅助方法
  allowCors(request, headers) {
    const origin = request.headers.get('origin');
    if (origin) {
      headers['Access-Control-Allow-Credentials'] = true;
      headers['Access-Control-Allow-Origin'] = this.getAllowedOrigin(origin);
      headers['Access-Control-Allow-Methods'] = 'POST';
      headers['Access-Control-Allow-Headers'] =
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version';
      headers['Access-Control-Max-Age'] = '600';
    }
  }

  getAllowedOrigin(origin) {
    const localhostRegex = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d{1,5})?$/;
    if (localhostRegex.test(origin)) {
      return origin;
    } else if (this.config.CORS_ALLOW_ORIGIN) {
      const corsList = this.config.CORS_ALLOW_ORIGIN.split(',');
      for (let i = 0; i < corsList.length; i++) {
        const cors = corsList[i].replace(/\/$/, '');
        if (cors === origin) {
          return origin;
        }
      }
      return '';
    } else {
      return origin;
    }
  }

  anonymousSignIn(event) {
    if (event.accessToken) {
      return event.accessToken;
    } else {
      return uuidv4().replace(/-/g, '');
    }
  }

  getUid() {
    return this.accessToken;
  }

  isAdmin() {
    const uid = this.getUid();
    return this.config.ADMIN_PASS === md5(uid);
  }

  getIp(request) {
    return request.headers.get('CF-Connecting-IP');
  }

  protect(request) {
    const ip = this.getIp(request);
    this.requestTimes[ip] = (this.requestTimes[ip] || 0) + 1;
    if (this.requestTimes[ip] > MAX_REQUEST_TIMES) {
      logger.warn(`${ip} 当前请求次数为 ${this.requestTimes[ip]}，已超过最大请求次数`);
      throw new Error('Too Many Requests');
    } else {
      logger.log(`${ip} 当前请求次数为 ${this.requestTimes[ip]}`);
    }
  }

  // 数据库操作相关方法
  async readConfig() {
    const configStr = await this.db.readConfigQuery.first('value');
    this.config = configStr ? JSON.parse(configStr) : {};
  }

  async writeConfig(newConfig) {
    if (!Object.keys(newConfig).length) return;
    logger.info('写入配置：', newConfig);
    try {
      const config = { ...this.config, ...newConfig };
      await this.db.writeConfigStmt.bind(JSON.stringify(config)).run();
      this.config = config;
    } catch (e) {
      logger.error('写入配置失败：', e);
    }
  }

  // Twikoo 功能方法
  async setPassword(event) {
    const isAdminUser = this.isAdmin();
    if (this.config.ADMIN_PASS && !isAdminUser) {
      return { code: RES_CODE.PASS_EXIST, message: '请先登录再修改密码' };
    }
    const ADMIN_PASS = md5(event.password);
    await this.writeConfig({ ADMIN_PASS });
    return {
      code: RES_CODE.SUCCESS
    };
  }

  async login(password) {
    if (!this.config) {
      return { code: RES_CODE.CONFIG_NOT_EXIST, message: '数据库无配置' };
    }
    if (!this.config.ADMIN_PASS) {
      return { code: RES_CODE.PASS_NOT_EXIST, message: '未配置管理密码' };
    }
    if (this.config.ADMIN_PASS !== md5(password)) {
      return { code: RES_CODE.PASS_NOT_MATCH, message: '密码错误' };
    }
    return {
      code: RES_CODE.SUCCESS
    };
  }

  async commentGet(event) {
    const res = {};
    try {
      validate(event, ['url']);
      const uid = this.getUid();
      const isAdminUser = this.isAdmin();
      const limit = parseInt(this.config.COMMENT_PAGE_SIZE) || 8;
      let more = false;
      const count = await this.db.commentCountQuery
        .bind(event.url, isAdminUser ? 2 : 1, uid)
        .first('count');

      const MAX_TIMESTAMP_MILLIS = 41025312000000;
      let { results: main } = await this.db.commentQuery
        .bind(
          event.url, isAdminUser ? 2 : 1, uid,
          event.before ?? MAX_TIMESTAMP_MILLIS, 0,
          limit + 1
        ).all();

      if (main.length > limit) {
        more = true;
        main.splice(limit, 1);
      }

      let top = [];
      if (!this.config.TOP_DISABLED && !event.before) {
        top = (await this.db.commentQuery
          .bind(
            event.url, isAdminUser ? 2 : 1, uid, MAX_TIMESTAMP_MILLIS, 1,
            500
          ).all()).results;
        main = [...top, ...main];
      }

      const { results: reply } = await this.db.getReplyQuery(main.length)
        .bind(
          event.url, isAdminUser ? 2 : 1, uid, ...main.map((item) => item._id)
        ).all();

      res.data = parseComment([...main, ...reply].map(this.parseLike), uid, this.config);
      res.more = more;
      res.count = count;
    } catch (e) {
      res.data = [];
      res.message = e.message;
    }
    return res;
  }

  parseLike(comment) {
    comment.like = JSON.parse(comment.like);
    return comment;
  }

  async commentGetForAdmin(event) {
    const res = {};
    const isAdminUser = this.isAdmin();
    if (isAdminUser) {
      validate(event, ['per', 'page']);
      const count = await this.db.commentForAdminCountQuery
        .bind(
          event.type === 'VISIBLE' ? 1 :
          event.type === 'HIDDEN' ? 0 :
          2,
          `%${event.keyword ?? ''}%`
        ).first('count');
      const { results: data } = await this.db.commentForAdminQuery.bind(
        event.type === 'VISIBLE' ? 1 :
        event.type === 'HIDDEN' ? 0 :
        2,
        `%${event.keyword ?? ''}%`,
        event.per,
        event.per * (event.page - 1)
      ).all();
      res.code = RES_CODE.SUCCESS;
      res.count = count;
      res.data = data;
    } else {
      res.code = RES_CODE.NEED_LOGIN;
      res.message = '请先登录';
    }
    return res;
  }

  async commentSetForAdmin(event) {
    const res = {};
    const isAdminUser = this.isAdmin();
    if (isAdminUser) {
      validate(event, ['id', 'set']);
      const fields = Object.keys(event.set).sort();
      await this.db.getCommentSetStmt(fields).bind(
        ...fields.map(field => event.set[field]), event.id,
      ).run();
      res.code = RES_CODE.SUCCESS;
    } else {
      res.code = RES_CODE.NEED_LOGIN;
      res.message = '请先登录';
    }
    return res;
  }

  async commentDeleteForAdmin(event) {
    const res = {};
    const isAdminUser = this.isAdmin();
    if (isAdminUser) {
      validate(event, ['id']);
      await this.db.commentDeleteStmt.bind(event.id).run();
      res.code = RES_CODE.SUCCESS;
    } else {
      res.code = RES_CODE.NEED_LOGIN;
      res.message = '请先登录';
    }
    return res;
  }

  async commentImportForAdmin(event) {
    const res = {};
    let logText = '';
    const log = (message) => {
      logText += `${new Date().toLocaleString()} ${message}\n`;
    };
    const isAdminUser = this.isAdmin();
    if (isAdminUser) {
      try {
        validate(event, ['source', 'file']);
        log(`开始导入 ${event.source}`);
        let comments;
        switch (event.source) {
          case 'valine': {
            const valineDb = await this.readFile(event.file, 'json', log);
            comments = await commentImportValine(valineDb, log);
            break;
          }
          case 'disqus': {
            const disqusDb = await this.readFile(event.file, 'xml', log);
            comments = await commentImportDisqus(disqusDb, log);
            break;
          }
          case 'artalk': {
            const artalkDb = await this.readFile(event.file, 'json', log);
            comments = await commentImportArtalk(artalkDb, log);
            break;
          }
          case 'artalk2': {
            const artalkDb = await this.readFile(event.file, 'json', log);
            comments = await commentImportArtalk2(artalkDb, log);
            break;
          }
          case 'twikoo': {
            const twikooDb = await this.readFile(event.file, 'json', log);
            comments = await commentImportTwikoo(twikooDb, log);
            break;
          }
          default:
            throw new Error(`不支持 ${event.source} 的导入，请更新 Twikoo 云函数至最新版本`);
        }
        for (const comment of comments) await this.save(comment);
        log(`导入成功`);
      } catch (e) {
        log(e.message);
      }
      res.code = RES_CODE.SUCCESS;
      res.log = logText;
      logger.info(logText);
    } else {
      res.code = RES_CODE.NEED_LOGIN;
      res.message = '请先登录';
    }
    return res;
  }

  async commentExportForAdmin() {
    const res = {};
    const isAdminUser = this.isAdmin();
    if (isAdminUser) {
      const { results: data } = await this.db.commentExportQuery.all();
      res.code = RES_CODE.SUCCESS;
      res.data = data;
    } else {
      res.code = RES_CODE.NEED_LOGIN;
      res.message = '请先登录';
    }
    return res;
  }

  async readFile(file, type, log) {
    try {
      let content = file.toString('utf8');
      log('评论文件读取成功');
      if (type === 'json') {
        content = jsonParse(content);
        log('评论文件 JSON 解析成功');
      } else if (type === 'xml') {
        content = await xml2js.parseStringPromise(content);
        log('评论文件 XML 解析成功');
      }
      return content;
    } catch (e) {
      log(`评论文件读取失败：${e.message}`);
    }
  }

  async commentLike(event) {
    const res = {};
    validate(event, ['id']);
    await this.like(event.id, this.getUid());
    return res;
  }

  async like(id, uid) {
    const comment = await this.db.commentByIdQuery.bind(id).first();
    if (!comment) return;
    let likes = JSON.parse(comment.like);
    if (likes.findIndex((item) => item === uid) === -1) {
      likes.push(uid);
    } else {
      likes = likes.filter((item) => item !== uid);
    }
    await this.db.updateLikeStmt.bind(id, JSON.stringify(likes)).run();
  }

  async commentSubmit(event, request) {
    const res = {};
    validate(event, ['url', 'ua', 'comment']);
    await this.limitFilter(request);
    await this.checkCaptcha(event, request);
    const data = await this.parse(event, request);
    const comment = await this.save(data);
    res.id = comment.id;

    try {
      logger.log('开始异步垃圾检测、发送评论通知');
      await Promise.race([
        (async () => {
          try {
            await this.postSubmit(comment);
          } catch (e) {
            logger.error('POST_SUBMIT 遇到错误');
            logger.error('请求参数：', comment);
            logger.error('错误信息：', e);
          }
        })(),
        new Promise((resolve) => setTimeout(resolve, 5000))
      ]);
      logger.log('POST_SUBMIT 完成');
    } catch (e) {
      logger.error('POST_SUBMIT 失败', e.message);
    }
    return res;
  }

  async save(data) {
    data.id = data._id = uuidv4().replace(/-/g, '');
    await this.db.saveCommentStmt.bind(
      data._id, data.uid ?? '', data.nick ?? '', data.mail ?? '', data.mailMd5 ?? '',
      data.link ?? '', data.ua ?? '', data.ip ?? '', data.master ?? 0,
      data.url, data.href, data.comment, data.pid ?? '', data.rid ?? '',
      data.isSpam ?? 0, data.created, data.updated,
      JSON.stringify(data.like ?? []), data.top ?? 0, data.avatar ?? ''
    ).run();
    return data;
  }

  async getParentComment(currentComment) {
    return this.db.commentByIdQuery.bind(currentComment.pid).first();
  }

  async postSubmit(comment) {
    const isSpam = await postCheckSpam(comment, this.config) ?? false;
    await this.saveSpamCheckResult(comment, isSpam);
    await sendNotice(comment, this.config, this.getParentComment.bind(this));
    return { code: RES_CODE.SUCCESS };
  }

  async parse(comment, request) {
    const timestamp = Date.now();
    const isAdminUser = this.isAdmin();
    const isBloggerMail = equalsMail(comment.mail, this.config.BLOGGER_EMAIL);
    if (isBloggerMail && !isAdminUser) throw new Error('请先登录管理面板，再使用博主身份发送评论');
    const hashMethod = this.config.GRAVATAR_CDN === 'cravatar.cn' ? md5 : sha256;
    const commentDo = {
      _id: uuidv4().replace(/-/g, ''),
      uid: this.getUid(),
      nick: comment.nick ? comment.nick : '匿名',
      mail: comment.mail ? comment.mail : '',
      mailMd5: comment.mail ? hashMethod(normalizeMail(comment.mail)) : '',
      link: comment.link ? comment.link : '',
      ua: comment.ua,
      ip: this.getIp(request),
      master: isBloggerMail,
      url: comment.url,
      href: comment.href,
      comment: xss(comment.comment),
      pid: comment.pid ? comment.pid : comment.rid,
      rid: comment.rid,
      isSpam: isAdminUser ? false : preCheckSpam(comment, this.config),
      created: timestamp,
      updated: timestamp
    };
    if (isQQ(comment.mail)) {
      commentDo.mail = addQQMailSuffix(comment.mail);
      commentDo.mailMd5 = md5(normalizeMail(commentDo.mail));
      commentDo.avatar = await getQQAvatar(comment.mail);
    }
    return commentDo;
  }

  async limitFilter(request) {
    let limitPerMinute = parseInt(this.config.LIMIT_PER_MINUTE);
    if (Number.isNaN(limitPerMinute)) limitPerMinute = 10;
    let limitPerMinuteAll = parseInt(this.config.LIMIT_PER_MINUTE_ALL);
    if (Number.isNaN(limitPerMinuteAll)) limitPerMinuteAll = 10;

    const getCountByIp = async () => limitPerMinute ?
      this.db.commentCountSinceByIpQuery.bind(
        Date.now() - 600000, this.getIp(request)
      ).first('count') : 0;
    const getCount = async () => limitPerMinuteAll ?
      this.db.commentCountSinceQuery.bind(Date.now() - 600000).first('count') : 0;
    const [countByIp, count] = await Promise.all([getCountByIp(), getCount()]);

    if (countByIp > limitPerMinute) throw new Error('发言频率过高');
    if (count > limitPerMinuteAll) throw new Error('评论太火爆啦 >_< 请稍后再试');
  }

  async checkCaptcha(comment, request) {
    if (this.config.TURNSTILE_SITE_KEY && this.config.TURNSTILE_SECRET_KEY) {
      await this.checkTurnstileCaptcha({
        ip: this.getIp(request),
        turnstileToken: comment.turnstileToken,
        turnstileTokenSecretKey: this.config.TURNSTILE_SECRET_KEY
      });
    }
  }

  async checkTurnstileCaptcha({ ip, turnstileToken, turnstileTokenSecretKey }) {
    try {
      const formData = new FormData();
      formData.append('secret', turnstileTokenSecretKey);
      formData.append('response', turnstileToken);
      formData.append('remoteip', ip);
      const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body: formData,
      });
      const data = await resp.json();
      logger.log('验证码检测结果', data);
      if (!data.success) throw new Error('验证码错误');
    } catch (e) {
      throw new Error('验证码检测失败: ' + e.message);
    }
  }

  async saveSpamCheckResult(comment, isSpam) {
    comment.isSpam = isSpam;
    await this.db.updateIsSpamStmt.bind(comment._id, isSpam, Date.now()).run();
  }

  async counterGet(event) {
    const res = {};
    try {
      validate(event, ['url']);
      await this.db.incCounterStmt.bind(event.url, event.title, Date.now()).run();
      res.time = await this.db.counterQuery.bind(event.url).first('time');
    } catch (e) {
      res.message = e.message;
      return res;
    }
    return res;
  }

  async getCommentsCount(event) {
    const res = {};
    try {
      validate(event, ['urls']);
      res.data = await Promise.all(event.urls.map(
        async (url) => ({
          url,
          count: await this.db.commentCountByUrlQuery
            .bind(url, event.includeReply)
            .first('count'),
        })));
    } catch (e) {
      res.message = e.message;
      return res;
    }
    return res;
  }

  async getRecentComments(event) {
    const res = {};
    try {
      if (event.pageSize > 100) event.pageSize = 100;
      let result;
      if (event.urls && event.urls.length) {
        result = await this.db.recentCommentsByUrlQuery.bind(
          1, '', event.includeReply, event.pageSize || 10
        ).all();
      } else {
        result = (await Promise.all(event.urls.map(
          (url) => this.db.recentCommentsByUrlQuery.bind(
            0, url, event.includeReply, event.pageSize || 10
          ).all()
        ))).flat();
      }
      res.data = result.map((comment) => {
        return {
          id: comment._id.toString(),
          url: comment.url,
          nick: comment.nick,
          avatar: getAvatar(comment, this.config),
          mailMd5: getMailMd5(comment),
          link: comment.link,
          comment: comment.comment,
          commentText: $(comment.comment).text(),
          created: comment.created
        };
      });
    } catch (e) {
      res.message = e.message;
      return res;
    }
    return res;
  }

  async setConfig(event) {
    const isAdminUser = this.isAdmin();
    if (isAdminUser) {
      await this.writeConfig(event.config);
      return {
        code: RES_CODE.SUCCESS
      };
    } else {
      return {
        code: RES_CODE.NEED_LOGIN,
        message: '请先登录'
      };
    }
  }

  async r2_upload(event, bucket, cdnUrl) {
    const { photo } = event;
    const res = {};
    try {
      if (cdnUrl.endsWith('/')) {
        cdnUrl = cdnUrl.substring(0, cdnUrl.length - 1);
      }
      const now = new Date();
      const year = now.getFullYear();
      const month = now.getMonth() + 1;
      const path = month < 10 ? `${year}/0${month}/` : `${year}/${month}/`;
      let filename = md5(photo);
      const blob = this.dataURIToBlob(photo);
      const mime = blob.type.split('/');
      if (mime.length > 1) {
        filename += '.' + mime[1].trim();
      }
      const object = await bucket.put(path + filename, blob);
      res.code = 0;
      res.data = {
        name: filename,
        size: object.size,
        etag: object.etag,
        url: `${cdnUrl}/${path}${filename}`
      };
    } catch (e) {
      logger.error(e);
      res.code = 1040;
      res.err = e.message;
    }
    return res;
  }

  dataURIToBlob(dataURI) {
    const [header, base64] = dataURI.split(',');
    const mime = header.match(/:(.*?);/)[1];
    const binaryString = atob(base64);
    const len = binaryString.length;
    const uint8Array = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      uint8Array[i] = binaryString.charCodeAt(i);
    }
    return new Blob([uint8Array], { type: mime });
  }
}
