# Texnokaktus.ProgOlymp.Identity

Библиотека настройки JWT Bearer-аутентификации для ASP.NET Core на .NET 10.
Проверяет подпись **RS256** по открытому RSA-ключу из PEM-файла.

## Подключение

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Texnokaktus.ProgOlymp.Identity.Extensions;

builder.Services
       .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
       .AddConfiguredJwtBearer(builder.Configuration);
builder.Services.AddAuthorization();

// После builder.Build():
app.UseAuthentication();
app.UseAuthorization();
```

По умолчанию библиотека читает `keys/jwt-public.pem` относительно
`AppContext.BaseDirectory` — каталога приложения, а не рабочей директории процесса.
Секция `JwtSettings` необязательна. При необходимости путь, issuer и audience
можно переопределить:

```json
{
  "JwtSettings": {
    "PublicKeyPath": "/run/keys/jwt-public.pem",
    "ClaimsIssuer": "Texnokaktus.ProgOlymp.Api",
    "Audience": "Texnokaktus.ProgOlymp.Api"
  }
}
```

Issuer и audience по умолчанию равны `Texnokaktus.ProgOlymp.Api`. Путь может быть
абсолютным или относительным. Через переменную окружения он задаётся как
`JwtSettings__PublicKeyPath`.

## Файл ключа

Поддерживаются один блок `PUBLIC KEY` (SubjectPublicKeyInfo) или `RSA PUBLIC KEY`
(PKCS#1) и RSA размером не менее 2048 бит. Закрытый ключ остаётся у издателя JWT.
Сертификаты, закрытые ключи и файлы с несколькими PEM-блоками не принимаются.

Пример создания пары ключей с OpenSSL:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

Проверяющему приложению нужен только `jwt-public.pem`. Ключ предоставляет
приложение или процесс развёртывания; библиотека не генерирует и не упаковывает его.
Например, для контейнера, приложение которого находится в `/app`, примонтируйте
публичный ключ только для чтения в `/app/keys/jwt-public.pem` либо задайте другой
путь через конфигурацию.

Файл читается при вызове `AddConfiguredJwtBearer`. Отсутствующий, недоступный или
некорректный файл приводит к ошибке регистрации аутентификации. После загрузки
проверка работает с ключом в памяти; изменение файла требует перезапуска приложения.
Срок действия токена проверяется со стандартным допуском времени IdentityModel.

## Переход с симметричной подписи

Это несовместимое изменение: `JwtSettings:IssuerSigningKey` больше не используется,
а HS256-токены не принимаются. Издатель должен подписывать токены соответствующим
закрытым RSA-ключом с алгоритмом RS256. Настройку необходимо обновить во всех
проверяющих сервисах. Claims и контракт ответа сервиса выпуска токенов можно сохранить.

У библиотеки сейчас один публичный ключ и нет сетевой загрузки или автоматической
ротации. Возможности следующего этапа описаны в [исследовании JWKS](docs/jwks-research.md).

## Разработка

- `src/` — библиотека.
- `tests/` — интеграционные тесты NUnit через Microsoft.Testing.Platform и TestHost.
- `Directory.Build.props` — общие параметры сборки; `tests/Directory.Build.props` — тестовая инфраструктура.
- `Directory.Packages.props` — централизованные версии NuGet-пакетов (CPM).
- `global.json` — выбор MTP для `dotnet test` в .NET SDK 10 и новее.

```sh
dotnet restore
dotnet build --no-restore
dotnet test --no-build
dotnet pack --configuration Release
```

Тесты создают временные ключи в каталоге выходной сборки и удаляют их после запуска.
