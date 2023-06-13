//Building ASP.NET Core Web APIs with Clean Architecture
//https://medium.com/c-sharp-progarmming/building-clean-architecture-application-using-asp-net-core-web-api-and-angular-11-backend-81b57c315dfa
//https://www.researchgate.net/publication/362234564_Clean_Architecture_in_Aspnet_Core_Web_API
//https://www.researchgate.net/publication/362234564_Clean_Architecture_in_Aspnet_Core_Web_API
//https://www.c-sharpcorner.com/article/clean-architecture-with-asp-net-core-webapi/

//asp.net core web api clean architecture github
//asp.net core clean architecture step by step
//asp.net core clean architecture github
//asp.net core architecture best practices
//clean architecture asp.net core 6
//asp.net core identity clean architecture
//web api architecture best practices c#
//asp.net clean architecture
using AspNetCore.Identity.Mongo;
using AspNetCore.Identity.MongoDbCore.Extensions;
using AspNetCore.Identity.MongoDbCore.Infrastructure;
//using UserAuthentications.Api.Models;11Jun
using UserAuthentications.Core.Entities;
using UserAuthentications.Infrastructure.Persistence;
using UserAuthentications.Operation.Abstractions;
using UserAuthentications.Operation.Implementation;
using UserAuthentications.Operation.MappingProfiles;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using MongoDbGenericRepository;
using SendGrid;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
// Register the DejavuDBSettings options

var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables()
                .Build();
//builder.Services.Configure<DejavuDBSettings>(config.GetSection(nameof(DejavuDBSettings)));11Jun

// Register the IMongoDbContext instance
//builder.Services.AddSingleton<IMongoDbContext>(provider =>
//{
//    var settings = provider.GetRequiredService<IOptions<DejavuDBSettings>>().Value;
//    var client = new MongoClient(settings.ConnectionString);
//    var database = client.GetDatabase(settings.DatabaseName);
//    return new MongoDbContext(database);
//});

// Add services to the container.
//builder.Services.Configure<DejavuDBSettings>(
//builder.Configuration.GetSection(nameof(DejavuDBSettings)));11Jun

//builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
//    .AddMongoDbStores<IdentityUser, IdentityRole, string>("mongodb://localhost:27017/identity")
//    .AddDefaultTokenProviders();

// Register the Identity services
//builder.Services.AddIdentityCore<ApplicationUser>(options =>
//{
//    options.Password.RequireDigit = true;
//    options.Password.RequireLowercase = true;
//    options.Password.RequireUppercase = true;
//    options.Password.RequireNonAlphanumeric = false;
//    options.Password.RequiredLength = 8;
//})
//    .AddMongoDbStores<ApplicationUser, IdentityRole, string>("DejavuDBSettings:ConnectionString")
//    .AddDefaultTokenProviders();

//builder.Services.AddAuthentication()
//   .AddGoogle(options =>
//   {
//       IConfigurationSection googleAuthNSection =
//       config.GetSection("Authentication:Google");
//       options.ClientId = googleAuthNSection["ClientId"];
//       options.ClientSecret = googleAuthNSection["ClientSecret"];
//   })
//   .AddFacebook(options =>
//   {
//       IConfigurationSection FBAuthNSection =
//       config.GetSection("Authentication:FB");
//       options.ClientId = FBAuthNSection["ClientId"];
//       options.ClientSecret = FBAuthNSection["ClientSecret"];
//   });
//.AddMicrosoftAccount(microsoftOptions =>
//{
//    microsoftOptions.ClientId = config["Authentication:Microsoft:ClientId"];
//    microsoftOptions.ClientSecret = config["Authentication:Microsoft:ClientSecret"];
//})
//.AddTwitter(twitterOptions =>
//{
//    twitterOptions.ConsumerKey = config["Authentication:Twitter:ConsumerAPIKey"];
//    twitterOptions.ConsumerSecret = config["Authentication:Twitter:ConsumerSecret"];
//    twitterOptions.RetrieveUserDetails = true;
//});

//builder.Services.AddAuthentication()
//        //.AddFacebook(options =>
//        //{
//        //    options.AppId = builder.Configuration["Authentication:Facebook:AppId"];
//        //    options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
//        //})
//        .AddGoogle(options =>
//        {
//            options.ClientId = "977119073212-86broul2astpqvc50qsrvjkgurslmaio.apps.googleusercontent.com";//builder.Configuration["Authentication:Google:ClientId"];
//            options.ClientSecret = "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";// builder.Configuration["Authentication:Google:ClientSecret"];
//        });

//builder.Services.AddCors(options =>
//{
//    options.AddPolicy("MyAllowedOrigins",
//        policy =>
//        {
//            policy.WithOrigins("https://localhost:8081") // note the port is included 
//                .AllowAnyHeader()
//                .AllowAnyMethod();
//        });
//});

//builder.Services.AddSingleton<IDejavuDBSettings>(sp =>
//    sp.GetRequiredService<IOptions<DejavuDBSettings>>().Value);11Jun

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

builder.Services.AddSingleton<IMongoClient>(s =>
    new MongoClient(builder.Configuration.GetValue<string>("DejavuDBSettings:ConnectionString")));
//builder.Services.AddScoped<ICountryService, CountryService>();11Jun

builder.Services.Configure<MongoDbOptions>(options =>
{
    options.ConnectionString = builder.Configuration.GetValue<string>("DejavuDBSettings:ConnectionString");
});
builder.Services.AddScoped<IAuthService, AuthService>();
//builder.Services.AddScoped<IUsernewService, UsernewService>();11Jun
//builder.Services.AddScoped<IUserRepository, UserRepository>();
//builder.Services.AddScoped<IAuthService, AuthService>();
//builder.Services.AddScoped<IAuthService, AuthService>();
//builder.Services.AddScoped<SignInManager<ApplicationUser>>();
////builder.Services.AddScoped<IAuthService, AuthService>();
//builder.Services.AddScoped<IPackageService, PackageService>();11Jun
//builder.Services.AddScoped<IPackagesnewService, PackagesnewService>();11Jun
//builder.Services.AddScoped<IBookingInfoService, BookingInfoService>();11Jun
//builder.Services.AddScoped<IMediaService, MediaService>();11Jun
builder.Services.AddScoped<ICacheService, CacheService>();
//builder.Services.AddScoped<IEmailService, EmailService>();11Jun
//builder.Services.AddScoped<IPaymentService, PaymentService>();1Jun
builder.Services.AddDistributedMemoryCache();
builder.Services.AddMongo();
//builder.Services.AddMongoRepository<Package>("package");11Jun
//builder.Services.AddMongoRepository<Packagesnew>("packagesnew");11Jun
//builder.Services.AddMongoRepository<BookingInfo>("BookingInfo");11Jun
//builder.Services.AddMongoRepository<Country>("country");11Jun
//builder.Services.AddMongoRepository<Media>("media");11Jun
//builder.Services.AddMongoRepository<State>("state");11Jun
builder.Services.AddMongoRepository<Usernew>("user");
builder.Services.AddControllers();

builder.Services.AddAutoMapper(typeof(PackageMappingProfile));
builder.Services.AddAutoMapper(typeof(PackagesnewMappingProfile));
builder.Services.AddAutoMapper(typeof(UsernewMappingProfile));
builder.Services.AddAutoMapper(typeof(BookingInfoMappingProfile));
//builder.Services.AddTransient<IEmailSender, EmailSender>(i =>
//                new EmailSender(
//builder.Configuration["EmailSender:Host"],
//                    builder.Configuration.GetValue<int>("EmailSender:Port"),
//                    builder.Configuration.GetValue<bool>("EmailSender:EnableSSL"),
//                    builder.Configuration["EmailSender:UserName"],
//                    builder.Configuration["EmailSender:Password"]
//                )
//            );

BsonClassMap.RegisterClassMap<PackageClassMap>();
BsonClassMap.RegisterClassMap<PackagesnewClassMap>();
BsonClassMap.RegisterClassMap<UsernewClassMap>();
BsonClassMap.RegisterClassMap<BookingInfo>();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(
            policy =>
            {
                policy.AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
    });
}

builder.Services.AddSingleton<ISendGridClient>(x =>
    new SendGridClient(config["SendGrid:ApiKey"]));

//builder.Services.AddControllers();
//builder.Services.AddSwaggerGen();

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = config["Jwt:Issuer"],
        ValidAudience = config["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:SecretKey"]))
    };
});
//var mongoDbContext = new MongoDbContext("mongodb://localhost:27017", "MongoDbTests");
//builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
//    .AddMongoDbStores<IMongoDbContext>(mongoDbContext)
//    .AddDefaultTokenProviders();

//var mongoDbContext = new MongoDbContext("mongodb://localhost:27017", "MongoDbTests");
//builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
//    .AddMongoDbStores<ApplicationUser, ApplicationRole, Guid>(mongoDbContext)
//    .AddDefaultTokenProviders();

var mongoDbIdentityConfiguration = new MongoDbIdentityConfiguration
{
    MongoDbSettings = new MongoDbSettings
    {
        ConnectionString = "mongodb+srv://application_user:iEvWT72cugkO6li2@cluster0.rocwou1.mongodb.net",
        DatabaseName = "dejavuTours"
    },
    IdentityOptionsAction = options =>
    {
        // Default Password settings.
        options.Password.RequiredUniqueChars = 1;
        options.Password.RequireDigit = false;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;

        // Default SignIn settings.
        options.SignIn.RequireConfirmedEmail = false;
        options.SignIn.RequireConfirmedPhoneNumber = false;

        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
        options.Lockout.MaxFailedAccessAttempts = 10;
        options.Lockout.AllowedForNewUsers = true;

        // ApplicationUser settings
        options.User.RequireUniqueEmail = true;
        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_";
    }
};
builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.Cookie.Name = "YourAppCookieName";
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.LoginPath = "/Identity/Account/Login";
    // ReturnUrlParameter requires 
    //using Microsoft.AspNetCore.Authentication.Cookies;
    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
    options.SlidingExpiration = true;
});
builder.Services.ConfigureMongoDbIdentity<ApplicationUser, ApplicationRole, Guid>(mongoDbIdentityConfiguration)
    .AddRoles<ApplicationRole>()
        .AddRoleManager<RoleManager<ApplicationRole>>()
                    .AddSignInManager()
        .AddDefaultTokenProviders();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
});
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });

    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Reference = new OpenApiReference
        {
            Type = ReferenceType.SecurityScheme,
            Id = JwtBearerDefaults.AuthenticationScheme
        }
    };

    c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, securityScheme);

    //c.AddSecurityRequirement(new OpenApiSecurityRequirement
    //{
    //    { securityScheme, new string[] { } }
    //});

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

// Use the mongoDbContext for other things.
//builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
//    .AddMongoDbStores<MongoDbContext>()
//    .AddDefaultTokenProviders();
//builder.Services.AddIdentityMongoDbProvider<ApplicationUser, IdentityRole>(options =>
//{
//    options.Password.RequireDigit = true;
//    options.Password.RequireLowercase = true;
//    options.Password.RequireUppercase = true;
//    options.Password.RequireNonAlphanumeric = false;
//    options.Password.RequiredLength = 8;
//})
//    .AddMongoDbStores<IMongoDbContext>()
//    .AddDefaultTokenProviders();

//builder.Services.AddSingleton<IMongoDbContext>(sp =>
//{
//    var settings = sp.GetRequiredService<IOptions<MongoDbSettings>>().Value;
//    return new MongoDbContext(settings.ConnectionString, settings.DatabaseName);
//});

//builder.Services.AddIdentity<ApplicationUser, MongoIdentityRole>()
//        .AddMongoDbStores<ApplicationUser, MongoIdentityRole, ObjectId>(MongoDbContextd)
//        .AddDefaultTokenProviders();

//builder.Services.AddIdentityMongoDbProvider<ApplicationUser, MongoIdentityRole>(options =>
//{
//    options.Password.RequiredLength = 8;
//    options.Password.RequireNonAlphanumeric = false;
//})
//.AddMongoDbStores<IMongoDbContext>()
//.AddDefaultTokenProviders();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

}

app.UseHttpsRedirection();

// Add authentication middleware
app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.UseCors();

app.Run();
