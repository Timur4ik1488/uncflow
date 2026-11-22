import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SecretAnalyzer } from '../src/analyzers/secrets/index.ts';
import { ScaAnalyzer } from '../src/analyzers/sca/index.ts';
import { SastAnalyzer } from '../src/analyzers/sast/index.ts';

const createProject = (): string => fs.mkdtempSync(path.join(os.tmpdir(), 'uncflow-analyzers-'));

function writeProjectFile(root: string, filePath: string, content: string): void {
  const fullPath = path.join(root, filePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content);
}

function testBase64RecoverableTokens(): void {
  const root = createProject();
  try {
    const token = 'q9mX2vK7pL4nR8sT';
    const encoded = Buffer.from(token).toString('base64');
    writeProjectFile(root, 'src/Auth.kt', `
class Auth {
  fun configure() {
    val encodedCredential = "$encoded"
    val credential = String(Base64.getDecoder().decode(encodedCredential), Charsets.UTF_8)
    client.setBearerAuth(credential)
    client.setBearerAuth(String(Base64.getDecoder().decode("$encoded"), Charsets.UTF_8))
  }
}
`.replaceAll('$encoded', encoded));
    const findings = new SecretAnalyzer().scanProject(root).filter(f => f.class === 'recoverable-token');
    assert.equal(findings.length, 2);
    assert.ok(findings.some(f => f.line === 4 && f.endLine === 6));
    assert.ok(findings.some(f => f.line === 7 && f.endLine === 7));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testGradleDependencyForms(): void {
  const root = createProject();
  try {
    writeProjectFile(root, 'build.gradle.kts', `
val groupVar = "org.example"
val dependency = "$groupVar:named-lib:1.2.0"
val strictVersion = "1.3.0"
dependencies {
  implementation(
    group = "org.example",
    name = "multi-lib",
    version = "1.1.0",
  )
  implementation(dependency)
  implementation("$groupVar:strict-lib") {
    version {
      strictly(strictVersion)
    }
  }
  implementation("org.example:locked-lib")
}
`);
    writeProjectFile(root, 'gradle.lockfile', `
org.example:locked-lib:1.0.0=compileClasspath
`);

    const analyzer = new ScaAnalyzer([
      {
        id: 'TEST-ADVISORY',
        group: 'org.example',
        artifact: 'multi-lib',
        ranges: [{ lower: '1.0.0', lowerInclusive: true, upper: '2.0.0', upperInclusive: false }]
      },
      {
        id: 'TEST-ADVISORY',
        group: 'org.example',
        artifact: 'named-lib',
        ranges: [{ lower: '1.0.0', lowerInclusive: true, upper: '2.0.0', upperInclusive: false }]
      },
      {
        id: 'TEST-ADVISORY',
        group: 'org.example',
        artifact: 'strict-lib',
        ranges: [{ lower: '1.0.0', lowerInclusive: true, upper: '2.0.0', upperInclusive: false }]
      },
      {
        id: 'TEST-ADVISORY',
        group: 'org.example',
        artifact: 'locked-lib',
        ranges: [{ lower: '1.0.0', lowerInclusive: true, upper: '2.0.0', upperInclusive: false }]
      }
    ]);

    const findings = analyzer.scanProject(root);
    assert.deepEqual(
      findings.map(f => `${f.artifact}:${f.version}`).sort(),
      ['locked-lib:1.0.0', 'multi-lib:1.1.0', 'named-lib:1.2.0', 'strict-lib:1.3.0']
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function testCorsRouteShadowingAndIdor(): void {
  const root = createProject();
  try {
    writeProjectFile(root, 'src/main/kotlin/SecurityConfig.kt', `
class SecurityConfig : WebMvcConfigurer {
  override fun addCorsMappings(registry: CorsRegistry) {
    registry.addMapping("/api/**")
      .allowedOriginPatterns("https://*.example.com")
      .allowCredentials(true)
  }
}
`);
    writeProjectFile(root, 'src/main/kotlin/RouteConfig.kt', `
class RouteConfig {
  fun configure(http: HttpSecurity) {
    http.authorizeHttpRequests {
      it.requestMatchers("/prefix/**").permitAll()
      it.requestMatchers("/prefix/staff/export").hasRole("STAFF")
      it.requestMatchers("/staff/export").permitAll()
      it.requestMatchers("/**").authenticated()
    }
  }
}
`);
    writeProjectFile(root, 'src/main/kotlin/DocumentController.kt', `
@RestController
class DocumentController(private val documentService: DocumentService) {
  @PutMapping("/{documentId}/approve")
  fun approve(@PathVariable documentId: Long) = documentService.updateDocument(documentId)
}
`);
    writeProjectFile(root, 'src/main/kotlin/DocumentService.kt', `
@Service
class DocumentService(private val documentRepository: DocumentRepository) {
  fun updateDocument(id: Long) = documentRepository.updateDocument(id)
}
`);
    writeProjectFile(root, 'src/main/kotlin/DocumentRepository.kt', `
@Repository
class DocumentRepository(private val namedParameterJdbcTemplate: NamedParameterJdbcTemplate) {
  fun updateDocument(id: Long) = namedParameterJdbcTemplate.update(
    "UPDATE documents SET status = 'approved' WHERE id = :id",
    mapOf("id" to id)
  )
  fun deleteDocument(id: Long) = namedParameterJdbcTemplate.update(
    "DELETE FROM documents WHERE id = :id",
    mapOf("id" to id)
  )
}
`);
    writeProjectFile(root, 'src/main/resources/schema.sql', `
CREATE TABLE documents (
  id BIGINT PRIMARY KEY,
  owner_user_id BIGINT NOT NULL,
  status TEXT NOT NULL
);
`);

    const findings = new SastAnalyzer().scanProject(root);
    const cors = findings.filter(f => f.class === 'credentialed-cors');
    assert.equal(cors.length, 1);
    const route = findings.filter(f => f.class === 'route-authorization');
    assert.ok(route.some(f => f.description?.includes('/prefix/**') && f.description.includes('/prefix/staff/export')));
    assert.ok(route.some(f => f.description?.includes('/staff/export') && f.description.includes('/**')));
    assert.ok(findings.some(f => f.class === 'object-authorization' && f.path.endsWith('DocumentRepository.kt')));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

testBase64RecoverableTokens();
testGradleDependencyForms();
testCorsRouteShadowingAndIdor();
console.log('Analyzer universal pattern tests passed');
