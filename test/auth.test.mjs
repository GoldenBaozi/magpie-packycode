// Regression for Magpie's prompted API sign-in contract (upstream PR #1).
import { test, beforeEach, afterEach } from "node:test"
import assert from "node:assert/strict"
import { PackycodeAuthPlugin } from "../index.mjs"

const originalFetch = globalThis.fetch
beforeEach(() => {
  globalThis.fetch = () => { throw new Error("sign-in must not make network requests") }
})
afterEach(() => { globalThis.fetch = originalFetch })

test("prompted system-token sign-in returns the key Magpie must save", async () => {
  const { auth } = await PackycodeAuthPlugin({})
  const method = auth.methods[0]
  const prompt = method.prompts.find((p) => p.key === "token")
  assert.equal(prompt?.type, "password")
  assert.equal(prompt.validate("  synthetic-token  "), undefined)
  const result = await method.authorize({ userID: " oidc_12345 ", endpoint: "cf", token: "  synthetic-token  " })
  assert.deepEqual(result, {
    type: "success",
    key: "synthetic-token",
    metadata: { mode: "token", userID: "12345", endpoint: "cf", email: "packyapi-12345" },
  })
  assert.equal((await method.authorize({ userID: "12345", token: "synthetic-token" })).metadata.endpoint, "slb")
  for (const token of [undefined, "", " \t\n "]) {
    assert.ok(prompt.validate(token))
    const failed = await method.authorize({ userID: "12345", token })
    assert.equal(failed.type, "failed")
    assert.equal(failed.key, undefined)
  }
})

test("prompted API-key sign-in preserves multiple keys and rejects blank input", async () => {
  const { auth } = await PackycodeAuthPlugin({})
  const method = auth.methods[1]
  const prompt = method.prompts.find((p) => p.key === "keys")
  assert.equal(prompt?.type, "password")
  assert.equal(prompt.validate("sk-first, sk-second sk-third"), undefined)
  for (const endpoint of [undefined, "www"]) {
    const result = await method.authorize({ endpoint, keys: "  sk-first, sk-second sk-third  " })
    assert.deepEqual(result, {
      type: "success",
      key: "sk-first, sk-second sk-third",
      metadata: { mode: "keys", endpoint: endpoint || "slb" },
    })
  }
  for (const keys of [undefined, "", " \t\n "]) {
    assert.ok(prompt.validate(keys))
    const failed = await method.authorize({ keys })
    assert.equal(failed.type, "failed")
    assert.equal(failed.key, undefined)
  }
})
