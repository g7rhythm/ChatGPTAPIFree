import moment from 'moment';

const UPSTREAM_URL = 'https://api.openai.com/v1/chat/completions';
const UPSTREAM_URL_AZU3 = 'https://gptgogoins.openai.azure.com/openai/deployments/gptgogodepl/chat/completions?api-version=2023-06-01-preview';
const UPSTREAM_URL_AZU4 = 'https://rhythgpt4.openai.azure.com/openai/deployments/gpt4_32k/chat/completions?api-version=2023-06-01-preview';
const TestToVoice_URL='https://eastasia.tts.speech.microsoft.com/cognitiveservices/v1'

const ORG_ID_REGEX = /\borg-[a-zA-Z0-9]{24}\b/g; // used to obfuscate any org IDs in the response text
const MAX_REQUESTS = 3000; // maximum number of requests per IP address per hour

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, BREW',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const STREAM_HEADERS = {
  'Content-Type': 'text/event-stream',
  'Connection': 'keep-alive',
};

// Define an async function that hashes a string with SHA-256
const sha256 = async (message) => {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
};

const randomChoice = (arr) => arr[Math.floor(Math.random() * arr.length)];

const obfuscateOpenAIResponse = (text) => text.replace(ORG_ID_REGEX, 'org-************************').replace(' Please add a payment method to your account to increase your rate limit. Visit https://platform.openai.com/account/billing to add a payment method.', '');

// Define an async function that hashes user IP address, UTC year, month, day, day of the week, hour and the secret key
//
// To implement IP-based rate limiting, we have to store users' IP addresses in a certain way. However, we want to protect
// users' privacy as much as possible. To achieve this, we use SHA-256 to calculate a digest value of the user's IP address
// along with the UTC year, month, day, day of the week, hour, and the secret key. The resulting digest not only depends on
// the user's IP address but is also unique to each hour, making the user's IP address hard to be determined. Moreover, the
// one-way nature of the SHA-256 algorithm implies that even if the digest value is compromised, it is almost impossible to
// reverse it to obtain the original IP address, ensuring the privacy and security of the user's identity.
const hashIp = (ip, utcNow, secret_key) => sha256(`${utcNow.format('ddd=DD.MM-HH+YYYY')}-${ip}:${secret_key}`);

const handleRequest = async (request, env,apikey_name) => {
  let requestBody;
  let bodyraw;
  let stream;
  try {
    requestBody = await request.json();
    stream = requestBody.stream;
    if (stream != null && stream !== true && stream !== false) {
      return new Response('The `stream` parameter must be a boolean value', { status: 400, headers: CORS_HEADERS });
    }
    bodyraw=JSON.stringify(requestBody);
  } catch (error) {
    bodyraw=request.body;
  }

 

  try {
    // Enforce the rate limit based on hashed client IP address
    apikey_name=apikey_name||'appkeys';
  
    
    const  appkeys  = (await env.kv.get(apikey_name, { type: 'json' })) || {};
    const utcNow = moment.utc();
    const clientIp = request.headers.get('CF-Connecting-IP');
    const clientIpHash = await hashIp(clientIp, utcNow, appkeys.SECRET_KEY);
    const rateLimitKey = `rate_limit_${clientIpHash}`;
    
    const { rateLimitCount = 0 } = (await env.kv.get(rateLimitKey, { type: 'json' })) || {};
    if (rateLimitCount > MAX_REQUESTS) {
      return new Response('Too many requests', { status: 429, headers: CORS_HEADERS });
    }

    // Forward a POST request to the upstream URL and return the response
    const api_key = randomChoice(appkeys.API_KEYS);
    
      let postUrl =UPSTREAM_URL;
    let heads= {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api_key}`,
        'User-Agent': 'curl/7.64.1',
        'api-key':`${api_key}`
      }
    if(apikey_name=='azu3_appkeys'){
      postUrl=UPSTREAM_URL_AZU3;    
    }else if(apikey_name=='azu4_appkeys'){
       postUrl=UPSTREAM_URL_AZU4;    
    }else if(apikey_name=='tts_appkeys'){
       postUrl=TestToVoice_URL;
      heads= {
        'Content-Type': 'application/ssml+xml',       
        'User-Agent': 'curl/7.64.1',
        'X-Microsoft-OutputFormat':'audio-16khz-128kbitrate-mono-mp3',
        'Ocp-Apim-Subscription-Key':`${api_key}`
      }
    }
    const upstreamResponse = await fetch(postUrl, {
      method: 'POST',
      headers:heads,
      body: bodyraw,
    });

    if (!upstreamResponse.ok) {
      const { status } = upstreamResponse;
      const text = await upstreamResponse.text();
      const textObfuscated = obfuscateOpenAIResponse(text);
      return new Response(`OpenAI API responded with:\n\n${textObfuscated}`, { status, headers: CORS_HEADERS });
    }

    // Update the rate limit information
    const rateLimitExpiration =  moment.utc().startOf('hour').add(1, 'hour').add(2, 'minutes').unix();
    await env.kv.put(rateLimitKey, JSON.stringify({ rateLimitCount: rateLimitCount + 1 }), { expiration: rateLimitExpiration });

    return new Response(upstreamResponse.body, {
      headers: {
        ...CORS_HEADERS,
        ...(stream && STREAM_HEADERS),
        'Cache-Control': 'no-cache',
      },
    });
  } catch (error) {
    return new Response(error.message, { status: 500, headers: CORS_HEADERS });
  }
};

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname.includes('/v1/chat/completions')==false ) {
      return new Response('Not found v1', { status: 404, headers: CORS_HEADERS });
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          ...CORS_HEADERS,
          'Access-Control-Max-Age': '1728000',
        },
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: CORS_HEADERS });
    }

  
    if (pathname=='/v1/chat/completions/3-5') {
      return handleRequest(request, env,"apikey35");
    }else   if (pathname=='/v1/chat/completions/azu3') {
      return handleRequest(request, env,"azu3_appkeys");
    }else   if (pathname=='/v1/chat/completions/azu4') {
      return handleRequest(request, env,"azu4_appkeys");
    }else   if (pathname=='/v1/chat/completions/ttsv1') {
      return handleRequest(request, env,"tts_appkeys");
    }
   
    return handleRequest(request, env);
  },
};
