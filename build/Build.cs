using Nuke.Common;
using Nuke.Common.CI.GitHubActions;
using Nuke.Common.IO;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Tools.GitVersion;
using Octokit;
using static Nuke.Common.Tools.DotNet.DotNetTasks;


[GitHubActions(
    "ci",
    GitHubActionsImage.UbuntuLatest,
    FetchDepth = 0,
    OnPushBranches = ["main", "master"],
    OnPushTags = ["v[0-9]+.[0-9]+.[0-9]+"],
    InvokedTargets = [nameof(GitHubBuild)],
    PublishArtifacts = true,
    AutoGenerate = false
)]
class Build : NukeBuild
{
    /// Support plugins are available for:
    ///   - JetBrains ReSharper        https://nuke.build/resharper
    ///   - JetBrains Rider            https://nuke.build/rider
    ///   - Microsoft VisualStudio     https://nuke.build/visualstudio
    ///   - Microsoft VSCode           https://nuke.build/vscode
    public static int Main() => Execute<Build>(x => x.Compile);

    [Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
    readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;
    
    [Parameter("Output directory for artifacts generated while packing and publishing.")]
    readonly AbsolutePath ArtifactsDirectory = AbsolutePath.Create(GitHubActions.Instance?.Workspace ?? RootDirectory) / "artifacts"; 
    
    [GitVersion(NoCache=false, NoFetch=true)]
    readonly GitVersion GitVersion;
    

    Target Clean => _ => _
        .Before(Restore)
        .Executes(() => {
            DotNetClean(config => config.SetConfiguration(Configuration));
        });

    Target Restore => _ => _
        .Executes(() => {
            DotNetRestore(config => config);
        });

    Target Compile => _ => _
        .DependsOn(Restore)
        .Executes(() => {
            DotNetBuild(config => config
                .SetConfiguration(Configuration)
                .EnableNoRestore()
                .SetAssemblyVersion(GitVersion.AssemblySemVer)
                .SetFileVersion(GitVersion.AssemblySemFileVer)
                .SetInformationalVersion(GitVersion.InformationalVersion)
            );
        });
    
    Target Test => _ => _
        .After(Compile)
        .Executes(() => {
            DotNetTest(config => config
                .SetConfiguration(Configuration)
                .EnableNoBuild()
            );
        });

    Target Pack => _ => _
        .After(Compile)
        .Produces(ArtifactsDirectory / "*.nupkg")
        .Produces(ArtifactsDirectory / "*.snupkg")
        .Executes(() => {
            DotNetPack(config => config
                .SetConfiguration(Configuration)
                .EnableNoBuild()
                .SetProperty("PackageVersion", GitVersion.NuGetVersion)
                .SetOutputDirectory(ArtifactsDirectory)
            );
        });
    
    Target GitHubBuild => _ => _
        .DependsOn(Compile)
        .DependsOn(Test)
        .DependsOn(Pack);
}