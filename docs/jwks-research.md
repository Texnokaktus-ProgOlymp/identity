# Публикация открытых ключей JWT через JWKS

Дата исследования: **26 октября 2026 года**.

## Задача и текущее состояние

Цель следующего этапа — позволить проверяющим сервисам получать открытые ключи
издателя по HTTPS без доставки PEM-файла в каждый контейнер. Самостоятельный выпуск
JWT этому не препятствует: публикация ключей отделена от способа аутентификации пользователя.

В библиотеке `Texnokaktus.ProgOlymp.Identity` реализована проверка RS256 по одному
открытому ключу из файла. Путь по умолчанию — `keys/jwt-public.pem` относительно
`AppContext.BaseDirectory`, переопределение — `JwtSettings:PublicKeyPath`.
Сетевой загрузки ключей и ротации в этой реализации нет.

В исследованном соседнем репозитории `Texnokaktus.ProgOlymp.Api`:

- `Texnokaktus.ProgOlymp.Api/Services/JwtAuthenticationService.cs` выпускает JWT
  через `JwtSecurityTokenHandler`, подписывая HS256 с общим секретом из Base64.
- `Texnokaktus.ProgOlymp.Api/Extensions/SecurityExtensions.cs` содержит собственную
  настройку проверки JWT и дополнительную проверку существования пользователя
  в `OnTokenValidated`.
- `Texnokaktus.ProgOlymp.Api/Settings/JwtSettings.cs` описывает issuer, audience,
  симметричный ключ и срок действия. В ответе `TokenModel` возвращаются токен и дата истечения.

Эти файлы изучены, но не изменены. Обновление одной библиотеки Identity не меняет
выпуск и собственную проверку JWT в API. Для сквозного перехода необходимо обновить
издателя и все реализации проверки; контракт claims и ответа можно сохранить.

## Discovery и JWKS

JWKS — JSON-документ с массивом `keys`, содержащим ключи в формате JWK.
Для RSA достаточно открытых параметров `n` и `e`; `kid` связывает ключ
с идентификатором в заголовке JWT. Поля `kty`, `use` и `alg` описывают тип,
назначение и алгоритм. Сертификат для публикации RSA-ключа не обязателен.
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html),
[параметры RSA в RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1).

Пример формы ответа `GET /.well-known/jwks.json` (значение `n` здесь условное):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "signing-key-1",
      "n": "<Base64url модуля RSA>",
      "e": "AQAB"
    }
  ]
}
```

Адрес JWKS можно опубликовать в discovery-документе
`GET /.well-known/openid-configuration`:

```json
{
  "issuer": "https://auth.example.com",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
}
```

Эти два поля достаточны для загрузки конфигурации и ключей рассматриваемым
`JwtBearer`/IdentityModel. Это подмножество метаданных для проверки JWT, а не
заявление о соответствии полному OpenID Connect: стандарт discovery требует
и другие поля для полноценного провайдера.
[OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata),
[загрузчик IdentityModel 8.19.2](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/8.19.2/src/Microsoft.IdentityModel.Protocols.OpenIdConnect/Configuration/OpenIdConnectConfigurationRetriever.cs).

Endpoint открытых ключей и метаданных доступны без аутентификации по HTTPS.
Закрытые параметры RSA (`d`, `p`, `q` и другие) и симметричные секреты публиковать
нельзя. В `JsonWebKeyConverter` нужно передавать ключ, содержащий только открытые
параметры: конвертер способен включить закрытые параметры, если они есть.
[JsonWebKeyConverter](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.jsonwebkeyconverter),
[безопасность публикации JWK](https://www.rfc-editor.org/rfc/rfc7517.html#section-9.2).

## Подключение потребителя

Вариант с привычным адресом discovery:

```csharp
builder.AddJwtBearer(options =>
{
    options.Authority = "https://auth.example.com";
    options.Audience = "Texnokaktus.ProgOlymp.Api";
    options.RequireHttpsMetadata = true;
    options.TokenValidationParameters.ValidAlgorithms =
        [SecurityAlgorithms.RsaSha256];
});
```

`Authority` задаёт базовый адрес: middleware добавляет
`/.well-known/openid-configuration`. `MetadataAddress` позволяет указать
полный адрес метаданных отдельно. Нельзя присвоить ему адрес самого JWKS:
сначала загружаются метаданные, затем документ по их `jwks_uri`.
[Исходники JwtBearer 10.0.12](https://github.com/dotnet/aspnetcore/blob/v10.0.12/src/Security/Authentication/JwtBearer/src/JwtBearerPostConfigureOptions.cs),
[MetadataAddress](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.jwtbearer.jwtbeareroptions.metadataaddress?view=aspnetcore-10.0).

Доверенный адрес задаёт конфигурация приложения, а не входящий JWT. Проверка
issuer, audience, срока действия и алгоритма остаётся обязательной.
Для стандартного OIDC discovery issuer должен быть HTTPS URL и точно совпадать
с `iss` токена. Текущее значение `Texnokaktus.ProgOlymp.Api` — логическое имя;
при переходе на стандартный issuer URL потребуется согласованная миграция.
[Проверка конфигурации discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation),
[настройка JWT Bearer](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0).

## Кеширование, доступность и ротация

IdentityModel кеширует конфигурацию и ключи в процессе. Запрос к издателю не нужен
для каждой проверки JWT. При отсутствии подходящего ключа `JwtBearer` по умолчанию
запрашивает обновление метаданных. Обновления ограничиваются интервалами;
не следует рассчитывать, что первый запрос с новым `kid` обязательно сразу пройдёт.
[RefreshOnIssuerKeyNotFound](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.jwtbearer.jwtbeareroptions.refreshonissuerkeynotfound?view=aspnetcore-10.0),
[ConfigurationManager](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.protocols.configurationmanager-1).

Рекомендуемая последовательность плановой ротации:

1. Создать новую пару ключей и новый `kid`, сохранив закрытый ключ у издателя.
2. Опубликовать новый открытый ключ в JWKS вместе со старым.
3. Дождаться распространения конфигурации с учётом настроенных интервалов
   обновления потребителей и промежуточных HTTP-кешей.
4. Начать подписывать новым ключом, добавляя его `kid` в заголовок JWT.
5. Сохранять старый открытый ключ до истечения всех выпущенных им токенов
   с учётом максимального TTL и допуска времени.

Это эксплуатационная рекомендация для данной архитектуры. Ключи должны сохраняться
между перезапусками, а экземпляры издателя — использовать согласованное хранилище.
Недоступность endpoint особенно критична для новых процессов без загруженного кеша.
Наличие кеша у работающего процесса не гарантирует бессрочную работу при сбое
издателя; это необходимо проверить с выбранной политикой обновления.
Удаление ключа из JWKS также не даёт мгновенного отзыва уже закешированных ключей.

## Варианты реализации сервера

| Вариант | Что предоставляет | Что остаётся приложению |
| --- | --- | --- |
| Компоненты Microsoft и Minimal API | `RsaSecurityKey`, `JsonWebKeyConverter`, `JsonWebKeySet`; стандартный клиент загрузки метаданных | Два endpoint, хранение, выбор активного ключа и ротация |
| `NetDevPack.Security.Jwt.AspNetCore` | Endpoint `/jwks`, сервис signing credentials, генерация и ротация ключей | Discovery-документ для `Authority`, настройка хранилища и согласование алгоритмов |
| OpenIddict | OAuth/OIDC server stack с discovery и JWKS | Интеграция протокольных потоков с собственной аутентификацией и постоянные credentials |

### Компоненты Microsoft

Отдельного готового Microsoft middleware для собственного JWKS-сервера
с автоматической ротацией в исследованных пакетах нет. Нужные примитивы уже есть
в `Microsoft.IdentityModel.Tokens`, а выпуск JWT — в
`System.IdentityModel.Tokens.Jwt`. `Microsoft.AspNetCore.Authentication.JwtBearer`
отвечает за потребление и проверку, а не за публикацию серверных endpoint.
[JsonWebKeySet](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.jsonwebkeyset),
[JsonWebKeyConverter](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.jsonwebkeyconverter),
[назначение JwtBearer](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0).

Для небольшого закрытого контура это минимальный по зависимостям вариант:
приложение публикует открытые параметры уже используемой ключевой пары.
Проектирование хранилища и ротации — отдельная часть работы.

### NetDevPack

На дату исследования `NetDevPack.Security.Jwt.AspNetCore` версии `10.0.0`
поддерживает .NET 10. `AddJwksManager()` регистрирует управление ключами,
`IJwtService.GetCurrentSigningCredentials()` возвращает credentials издателю,
а `UseJwksDiscovery()` публикует набор открытых ключей по `/jwks`.
Название discovery здесь относится именно к JWKS; OIDC discovery-документ
нужно добавить отдельно. Есть хранилища через Data Protection, EF Core и файловую
систему. По текущей документации алгоритм подписи по умолчанию — PS256;
для нашего RS256 потребуется явная настройка.
[NuGet](https://www.nuget.org/packages/NetDevPack.Security.Jwt.AspNetCore/10.0.0),
[документация проекта](https://github.com/NetDevPack/Security.Jwt#readme),
[ASP.NET Core integration](https://github.com/NetDevPack/Security.Jwt/blob/master/docs/Architecture/AspNetCore-Integration.md).

В API уже настроен Data Protection с Redis. Это полезный исходный контекст,
но пригодность такого хранилища для выбранной версии NetDevPack, формат,
разделение ключей и поведение нескольких экземпляров нужно проверить перед внедрением.

### OpenIddict

OpenIddict поддерживает ASP.NET Core 10 и предоставляет серверные discovery/JWKS
endpoint. Он подходит, если следующим шагом нужны стандартные OAuth/OIDC-потоки.
Интеграция шире публикации двух документов: необходимо настроить сервер,
credentials и обработку нужных протокольных запросов.
[ASP.NET Core integration](https://documentation.openiddict.com/integrations/aspnet-core),
[signing credentials](https://documentation.openiddict.com/configuration/encryption-and-signing-credentials),
[стандартные адреса endpoint](https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Server/OpenIddictServerOptions.cs).

## Вывод для следующего этапа

Согласованный первый шаг — файловый открытый ключ и RS256 в библиотеке проверки.
Для последующего устранения доставки PEM потребителям достаточно добавить
discovery/JWKS к издателю и загрузку метаданных в проверяющих сервисах.
При текущем небольшом объёме предпочтительный кандидат — компоненты Microsoft
и собственные Minimal API endpoint. Если нужна готовая автоматическая ротация,
стоит отдельно оценить NetDevPack и его хранилище. Выбор полноценного OpenIddict
имеет смысл вместе с потребностью в OAuth/OIDC-потоках.

Перед переходом необходимо согласовать срок жизни старых токенов, порядок
развёртывания, issuer и алгоритм. Дополнительную проверку пользователя
в `OnTokenValidated` следует сохранить независимо от источника открытых ключей.
