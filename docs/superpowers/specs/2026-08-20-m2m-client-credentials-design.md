# M2M авторизация: client_credentials + private_key_jwt

## Контекст

Нужно, чтобы ServiceA мог получать access token для вызова ServiceB через этот
auth service. ServiceA подписывает запрос своим приватным ключом; auth service
проверяет его публичным ключом и выпускает токен, ограниченный аудиторией
ServiceB.

Проект уже использует `better-auth` с плагинами `jwt()` и `oauthProvider()`
(`@better-auth/oauth-provider`). Схема БД (`oauth_client`,
`oauth_client_assertion`, `oauth_access_token`) уже подготовлена под OAuth2
`client_credentials` grant с `private_key_jwt` client-аутентификацией
(RFC 7523) — это встроенный механизм плагина, не кастомный код.

## Решение

Используем встроенный `client_credentials` grant + `private_key_jwt`
из `@better-auth/oauth-provider`. Реализация — конфигурация существующих
плагинов и одноразовая регистрация клиента, без нового кастомного кода
авторизации.

### Компоненты

1. **`admin` плагин** (`better-auth/plugins`) добавляется в `plugins[]` в
   `src/auth.ts`. Даёт `user.role` (и `banned`) через миграцию схемы.
   Используется только для одной цели: определить, кто может регистрировать
   OAuth-клиентов.

2. **Конфигурация `oauthProvider`** в `src/auth.ts`:
   - `resources: [{ identifier: "<resource-id ServiceB>", allowedScopes: [...] }]`
     — произвольная строка-идентификатор ServiceB (не обязан быть реальным URL).
   - `enforcePerClientResources: true` (значение по умолчанию, оставляем явно
     не меняем) — гарантирует, что клиент не получит токен для resource, к
     которому не привязан.
   - `clientPrivileges: async ({ action, user }) => action === "create" ? user?.role === "admin" : true`
     — ограничивает `POST /oauth2/create-client` только пользователями с
     `role === "admin"`.

3. **Регистрация ServiceA как OAuth-клиента** — через уже встроенный
   endpoint `POST /oauth2/create-client` (часть `oauthProvider()`, отдельный
   route не пишем). Требует сессии пользователя с `role === "admin"`. Тело
   запроса:
   - `token_endpoint_auth_method: "private_key_jwt"`
   - `jwks: { keys: [<публичный ключ ServiceA>] }` (статический JWKS,
     без `jwksUri`)
   - `client_credentials_scopes: [...]`
   - привязка к resource ServiceB (через `resources`/`allowedScopes`
     конфигурации выше)

4. **Первый admin-пользователь** — назначается вручную одноразовым SQL
   `UPDATE user SET role = 'admin' WHERE email = ...` после обычной
   регистрации через email/password. Задокументировать в README.

5. **ServiceB** не регистрируется как OAuth-клиент. Он получает access
   token в запросе от ServiceA и валидирует его самостоятельно:
   - тянет JWKS с `GET /jwks` auth service (кеширует у себя — вне объёма
     этой задачи, т.к. ServiceB не часть этого репозитория),
   - проверяет подпись, `aud` (== его resource identifier), нужный scope.

### Поток запроса токена

```
ServiceA -> POST /oauth2/token
  grant_type=client_credentials
  client_assertion=<JWT подписан приватным ключом ServiceA>
  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
  resource=<resource-id ServiceB>

auth service:
  - проверяет client_assertion: подпись (по зарегистрированному jwks),
    iss/sub == client_id, aud == token endpoint, exp не истёк,
    jti не использован ранее (replay-guard через oauth_client_assertion)
  - выпускает access token (JWT) с aud=<resource-id ServiceB>,
    scope из client_credentials_scopes ∩ запрошенных

ServiceA -> вызывает ServiceB с access token в Authorization: Bearer

ServiceB:
  - проверяет подпись через JWKS auth service
  - проверяет aud == себя, scope
  - обслуживает запрос
```

### Обработка ошибок

Стандартные OAuth2-ошибки от плагина (`invalid_client`, `invalid_grant`,
`invalid_target` для resource и т.д.) — кастомную обработку не добавляем.

### Тестирование

Интеграционный тест локально (`wrangler dev` + D1 local):
1. Сгенерировать тестовую key pair (для "ServiceA").
2. Создать admin-пользователя (email/password + прямой SQL `role='admin'`).
3. Через `/oauth2/create-client` (с сессией админа) зарегистрировать
   ServiceA-клиента с `private_key_jwt` + статическим `jwks`.
4. Запросить токен через `client_credentials` + `client_assertion`,
   проверить `aud`/`scope`/подпись через `/jwks`.
5. Негативные кейсы: просроченный `client_assertion`, повторное
   использование `jti` (replay), запрос `resource`, к которому клиент не
   привязан.

## Вне объёма

- Матрица прав нескольких сервисов с разными resource/scope — сейчас
  только один сценарий ServiceA → ServiceB.
- Ротация ключей ServiceA через `jwksUri` — используется статический
  `jwks`, обновляется вручную при необходимости.
- HTTP admin UI для управления клиентами — используется только встроенный
  `/oauth2/create-client`.
- Логика валидации токена на стороне ServiceB — вне этого репозитория.
