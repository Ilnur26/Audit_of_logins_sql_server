CREATE EVENT SESSION [Audit_Logon] ON SERVER 
ADD EVENT sqlserver.LOGIN (
    SET  collect_database_name = (1)    
        ,collect_options_text = (0) 
    ACTION(
         sqlserver.client_app_name
        ,sqlserver.client_hostname
        ,sqlserver.server_principal_name
    )
)
WITH (
     MAX_MEMORY = 4096 KB
    ,EVENT_RETENTION_MODE = ALLOW_SINGLE_EVENT_LOSS
    ,MAX_DISPATCH_LATENCY = 30 SECONDS
    ,MAX_EVENT_SIZE = 0 KB
    ,MEMORY_PARTITION_MODE = NONE
    ,TRACK_CAUSALITY = OFF
    ,STARTUP_STATE = ON
)
GO

CREATE TABLE [dbo].[AuditLogin](
    [LoggingID] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY CLUSTERED,
    [LoginName] [sysname] NOT NULL,
    [HostName] [varchar](100) NULL,
    [NTUserName] [varchar](100) NULL,
    [NTDomainName] [varchar](100) NULL,
    [ApplicationName] [varchar](340) NULL,
    [DatabaseName] [nvarchar](4000) NULL,
    [FirstSeen] [datetime] NULL,
    [LastSeen] [datetime] NULL,
    [LogonCount] [bigint] NULL,
) 
GO

CREATE UNIQUE NONCLUSTERED INDEX [IX_AuditLogon] ON [dbo].[AuditLogin]
(
    [LoginName] ASC,
    [HostName] ASC,
    [ApplicationName] ASC,
    [DatabaseName] ASC
)
GO

CREATE TABLE [dbo].[AuditLogin_Staging](
    [event_date] [datetime] NULL,
    [original_login] [nvarchar](128) NULL,
    [host_name] [nvarchar](128) NULL,
    [program_name] [nvarchar](255) NULL,
    [database_name] [nvarchar](128) NULL
)
GO

USE master
GO

CREATE PROCEDURE [dbo].[sp_ConsolidateAuditLogin]
AS
BEGIN

    SET NOCOUNT ON;

    IF OBJECT_ID('tempdb..#AuditLogin_Staging') IS NOT NULL
        DROP TABLE #AuditLogin_Staging;

    CREATE TABLE #AuditLogin_Staging(
        [event_date] [datetime] NULL,
        [original_login] [nvarchar](128) NULL,
        [host_name] [nvarchar](128) NULL,
        [program_name] [nvarchar](255) NULL,
        [database_name] [nvarchar](128) NULL
    );


    DELETE 
    FROM dbo.AuditLogin_Staging
    OUTPUT DELETED.* INTO #AuditLogin_Staging;




    MERGE INTO [AuditLogin] AS AuditLogin
    USING (
        SELECT MAX(event_date), original_login, host_name, program_name, database_name
            ,NtDomainName = CASE SSP.type WHEN 'U' THEN LEFT(SSP.name,CHARINDEX('\',SSP.name,1)-1) ELSE '' END
            ,NtUserName = CASE SSP.type WHEN 'U' THEN RIGHT(SSP.name,LEN(ssp.name) - CHARINDEX('\',SSP.name,1)) ELSE '' END
            ,COUNT(*)
        FROM #AuditLogin_Staging AS ALA
        INNER JOIN sys.server_principals AS SSP
            ON ALA.original_login = SSP.name
        GROUP BY original_login, host_name, program_name, database_name
            ,CASE SSP.type WHEN 'U' THEN LEFT(SSP.name,CHARINDEX('\',SSP.name,1)-1) ELSE '' END
            ,CASE SSP.type WHEN 'U' THEN RIGHT(SSP.name,LEN(ssp.name) - CHARINDEX('\',SSP.name,1)) ELSE '' END
    ) AS src (PostTime,LoginName,HostName,ApplicationName,DatabaseName,NtDomainName,NtUserName,LogonCount)
        ON AuditLogin.ApplicationName = src.ApplicationName
        AND AuditLogin.LoginName = src.LoginName
        AND AuditLogin.HostName = src.HostName
        AND AuditLogin.DatabaseName = src.DatabaseName
    WHEN MATCHED THEN 
        UPDATE SET
             LastSeen   = GETDATE()
            ,LogonCount += src.LogonCount
    WHEN NOT MATCHED THEN
        INSERT (
             LoginName
            ,HostName
            ,NTUserName
            ,NTDomainName
            ,ApplicationName
            ,DatabaseName
            ,FirstSeen
            ,LastSeen
            ,LogonCount
        )
        VALUES (
             src.LoginName
            ,src.HostName
            ,src.NTDomainName
            ,src.NTUserName
            ,src.ApplicationName
            ,src.DatabaseName
            ,src.PostTime
            ,src.PostTime
            ,src.LogonCount
        );
END
go

CREATE PROCEDURE sp_LoginDisabling
AS
BEGIN

	SET NOCOUNT ON;

	declare @mindate datetime, @login sysname, @tsql nvarchar(500);

	set @mindate = (select min(FirstSeen) from [master].[dbo].[AuditLogin]);

	create table #OverduedLogins(id int identity, LoginName sysname);

	insert into #OverduedLogins(LoginName)
	select sp.name
	from sys.server_principals sp
	where sp.[type] in ( 'U','S','C')
	and not exists(select* from [master].[dbo].[AuditLogin] al where al.LoginName = sp.name)
	and @mindate < dateadd(dd, datediff(dd, 0, getdate()) - 90, 0) -- находим кто никогда не логинился(по нашему логу), а логу уже больше 90 дней
	union
	select al.LoginName
	from [master].[dbo].[AuditLogin] al
	where al.LastSeen < dateadd(dd, datediff(dd, 0, getdate()) - 90, 0); -- все, кто есть в логе, но не логинился 90 дней и более
	
	DECLARE c CURSOR LOCAL FAST_FORWARD
	FOR
	SELECT l.LoginName
	FROM #OverduedLogins l
	ORDER BY l.id;
	OPEN c;
	FETCH c INTO @login;
	WHILE (@@FETCH_STATUS = 0)
	BEGIN
		set @tsql = N'ALTER LOGIN [' + @login + '] DISABLE;'
		exec sp_executesql @tsql;
	FETCH c INTO @login;
	END
	CLOSE c;
	DEALLOCATE c;

END

/*
SELECT * FROM [master].[dbo].[AuditLogin_Staging]

select * from [master].[dbo].[AuditLogin]
*/