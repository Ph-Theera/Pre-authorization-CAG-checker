export default {
  async fetch() {
    const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
    return Response.json({
      googleClientId,
      recordEnabled: Boolean(googleClientId && process.env.APPS_SCRIPT_URL && process.env.APPS_SCRIPT_SECRET)
    }, {headers:{'cache-control':'no-store'}});
  }
};
