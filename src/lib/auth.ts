import { Elysia, t } from "elysia";
import { generateState, OAuth2Tokens, generateCodeVerifier } from "arctic";
import { discord, google } from "./oauth";
import { db } from "./db";
import {
  createSession,
  generateSessionToken,
  setSessionTokenCookie,
  validateSessionToken,
  decodeIdToken
} from "./utils";
import { User } from "@prisma/client";

export const auth = new Elysia()
  .get("/login/discord", ({ cookie: { discord_oauth_state } }) => {
    const state = generateState();
    const scopes = ["identify"];
    const url = discord.createAuthorizationURL(state, scopes);

    discord_oauth_state.set({
      value: state,
      path: "/",
      httpOnly: true,
      maxAge: 60 * 10,
      sameSite: "lax",
    });

    return new Response(null, {
      status: 302,
      headers: {
        Location: url.toString(),
      },
    });
  })

  .get(
    "/callback/discord",
    async ({ query, cookie }) => {
      const code = query.code;
      const state = query.state;
      const storedState = cookie.discord_oauth_state.value;

      if (code === null || state === null || storedState === null) {
        return new Response(null, {
          status: 400,
        });
      }
      if (state !== storedState) {
        return new Response(null, {
          status: 400,
        });
      }

      let tokens: OAuth2Tokens;
      try {
        tokens = await discord.validateAuthorizationCode(code);
      } catch (e) {
        // Invalid code or client credentials
        return new Response(null, {
          status: 400,
        });
      }
      const discordUserResponse = await fetch(
        "https://discord.com/api/v10/users/@me",
        {
          headers: {
            Authorization: `Bearer ${tokens.accessToken()}`,
          },
        }
      );
      const discordUser = await discordUserResponse.json() as User;
      const existingUser = await db.user.findUnique({
        where: {
          discordId: discordUser.id,
        },
      });

      if (existingUser) {
        const sessionToken = generateSessionToken();
        const session = await createSession(sessionToken, existingUser.id);
        setSessionTokenCookie(cookie.session, sessionToken, session.expiresAt);
        return new Response(null, {
          status: 302,
          headers: {
            Location: "/",
          },
        });
      }

      const user = db.user.create({
        data: {
          email: discordUser.email,
          discordId: discordUser.id,
          username: discordUser.username,
          name: discordUser.username.split(" ")[0],
          avatar: discordUser.avatar,
        },
      });

      const sessionToken = generateSessionToken();
      const session = await createSession(sessionToken, (await user).id);
      setSessionTokenCookie(cookie.session, sessionToken, session.expiresAt);

      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
        },
      });
    },
    {
      query: t.Object({
        code: t.String(),
        state: t.Optional(t.String()),
      }),
      cookie: t.Object({
        discord_oauth_state: t.Optional(t.String()),
        session: t.Optional(t.String()),
        user_id: t.Optional(t.String()),
      }),
    }
  )
  .get("/login/google", ({ cookie: { google_oauth_state, google_code_verifier } }) => {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const scopes = ["openid", "profile", "email"];
    const url = google.createAuthorizationURL(state, codeVerifier, scopes);

    google_oauth_state.set({
      value: state,
      path: "/",
      httpOnly: true,
      maxAge: 60 * 10,
      sameSite: "lax",
    });

    google_code_verifier.set({
      value: codeVerifier,
      path: "/",
      httpOnly: true,
      maxAge: 60 * 10,
      sameSite: "lax",
    });

    return Response.redirect(url, 302); // IDK what 302 means here,have to check later
  })
  .get(
    "/callback/google",
    async ({ query, cookie: { google_oauth_state, google_code_verifier, session: sessionCookie } }) => {
      const cookie = { google_oauth_state, google_code_verifier, session: sessionCookie };
      const { code, state } = query;
      const storedState = google_oauth_state.value;
      const codeVerifier = google_code_verifier.value;

      if (!storedState || !state || storedState !== state || !code || !codeVerifier) {
        throw new Error("Invalid state, code, or code verifier");
      }

      let tokens: OAuth2Tokens;
      try {
        tokens = await google.validateAuthorizationCode(code, codeVerifier);
      } catch (e) {
        return new Response(null, {
          status: 400,
        });
      }

      const claims = decodeIdToken(tokens.idToken());
      const googleId = claims.sub;
      const name = claims.name || '';
      const email = claims.email || '';
      const picture = claims.picture || '';

      const existingUser = await db.user.findUnique({
        where: { googleId},
      })

      if (existingUser) {
        const sessionToken = generateSessionToken();
        const session = await createSession(sessionToken, existingUser.id);
        setSessionTokenCookie(cookie.session, sessionToken, session.expiresAt);
        return Response.redirect("/", 302);
      }

      const user = await db.user.create({
        data: {
          googleId,
          email,
          name,
          avatar: picture,
          username: email.split('@')[0], // Create username from email
        },
      });

      const sessionToken = generateSessionToken();
      const session = await createSession(sessionToken, user.id);
      setSessionTokenCookie(cookie.session, sessionToken, session.expiresAt);

      return Response.redirect("/", 302);
    },
    {
      query: t.Object({
        code: t.String(),
        state: t.Optional(t.String()),
      }),
      cookie: t.Object({
        google_oauth_state: t.Optional(t.String()),
        google_code_verifier: t.Optional(t.String()),
        session: t.Optional(t.String()),
      }),
    }
  )
  .get(
    "/validate",
    async ({ cookie }) => {
      if (!cookie.session.value) {
        return JSON.stringify({
          unauthorized: true,
        });
      }
      const auth = await validateSessionToken(cookie.session.value);
      if (auth.session === null || auth.user === null) {
        return JSON.stringify({
          unauthorized: true,
        });
      }

      return JSON.stringify({
        unauthorized: false,
      });
    },
    {
      cookie: t.Object({
        session: t.Optional(t.String()),
      }),
    }
  );
