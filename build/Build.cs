using System;
using System.Linq;
using Nuke.Common;
using Nuke.Common.CI;
using Nuke.Common.CI.GitHubActions;
using Nuke.Common.Execution;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tooling;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Tools.GitVersion;
using Nuke.Common.Utilities.Collections;
using static Nuke.Common.EnvironmentInfo;
using static Nuke.Common.IO.FileSystemTasks;
using static Nuke.Common.IO.PathConstruction;
using static Nuke.Common.Tools.DotNet.DotNetTasks;

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
            DotNetClean(c => c.SetConfiguration(Configuration));
        });

    Target Restore => _ => _
        .Executes(() => {
            DotNetRestore();
        });

    Target Compile => _ => _
        .DependsOn(Restore)
        .Executes(() => {
            DotNetBuild(c => c
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
            DotNetTest(c => c
                .SetConfiguration(Configuration)
                .EnableNoBuild()
            );
        });

    Target Pack => _ => _
        .After(Compile)
        .Produces(ArtifactsDirectory / "*.nupkg")
        .Produces(ArtifactsDirectory / "*.snupkg")
        .Executes(() => {
            DotNetPack(settings => settings
                .SetConfiguration(Configuration)
                .EnableNoBuild()
                .SetProperty("PackageVersion", GitVersion.NuGetVersion)
                .SetOutputDirectory(ArtifactsDirectory)
            );
        });
}