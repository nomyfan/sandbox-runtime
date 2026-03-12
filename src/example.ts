import { SandboxManager, type SandboxRuntimeConfig } from '.'
import { spawn } from 'child_process'

async function main() {
  const config: SandboxRuntimeConfig = {
    network: {
      deniedDomains: [],
      allowedDomains: ['*'],
    },
    filesystem: {
      allowWrite: ['/tmp/myapp'],
      denyRead: ['/etc/passwd'],
      denyWrite: ['/tmp/myapp/secrets'],
    },
  }

  await SandboxManager.initialize(config)

  // Wrap a command with sandbox restrictions
  const sandboxedCommand = await SandboxManager.wrapWithSandbox(
    'mkdir -p /tmp/myapp && echo ok > /tmp/myapp/test.txt && cat /tmp/myapp/test.txt && rm -rf /tmp/myapp',
  )

  // Execute the sandboxed command
  const child = spawn(sandboxedCommand, { shell: true, stdio: 'inherit' })

  // Handle exit and cleanup after child process completes
  child.on('exit', async code => {
    console.log(`Command exited with code ${code}`)
    // Cleanup when done (optional, happens automatically on process exit)
    await SandboxManager.reset()
  })
}

main().catch(err => {
  console.error('Error in sandbox example:', err)
})
