import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Resolve @google/generative-ai from scripts/skill-token-counter if not in root node_modules
const requireFromTokenCounter = createRequire(
  path.join(__dirname, 'skill-token-counter', 'package.json')
);

const EXCLUDED_SKILLS = new Set([
  'developing-genkit-dart',
  'developing-genkit-go',
  'developing-genkit-js',
  'developing-genkit-python',
  'xcode-project-setup',
  'firebase-hosting-basics',
  'firebase-app-hosting-basics',
  'extension-to-functions-codebase',
]);

const EXCLUDED_FILE_PATTERNS = [/ios/i, /web/i, /flutter/i];

function shouldExcludeFile(relativePathFromSkillRoot) {
  const basename = path.basename(relativePathFromSkillRoot);
  if (basename === 'SKILL.md') return false;
  return EXCLUDED_FILE_PATTERNS.some((pattern) => pattern.test(basename));
}

function splitFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) {
    return { rawFrontmatter: '', body: content };
  }
  return { rawFrontmatter: match[1], body: match[2] };
}

/**
 * Extracts top-level YAML blocks from frontmatter so we can deterministically
 * sync non-prose fields (like `metadata`, `version`, `compatibility`) without
 * needing an LLM call when only metadata changes on `main`.
 */
function parseFrontmatterBlocks(rawFrontmatter) {
  const blocks = new Map();
  let currentKey = null;
  let currentLines = [];

  for (const line of rawFrontmatter.split('\n')) {
    const topLevelMatch = line.match(/^([a-zA-Z0-9_-]+):(.*)$/);
    if (topLevelMatch) {
      if (currentKey !== null) {
        blocks.set(currentKey, currentLines.join('\n'));
      }
      currentKey = topLevelMatch[1];
      currentLines = [line];
    } else if (currentKey !== null) {
      currentLines.push(line);
    }
  }
  if (currentKey !== null) {
    blocks.set(currentKey, currentLines.join('\n'));
  }
  return blocks;
}

function mergeMetadataBlocks(mainMetadataBlock, targetMetadataBlock) {
  if (!mainMetadataBlock) return targetMetadataBlock;
  if (!targetMetadataBlock) return mainMetadataBlock;

  const parseSubKeys = (block) => {
    const map = new Map();
    for (const line of block.split('\n').slice(1)) {
      const m = line.match(/^\s+([a-zA-Z0-9_-]+):\s*(.*)$/);
      if (m) {
        map.set(m[1], line);
      }
    }
    return map;
  };

  const mainSub = parseSubKeys(mainMetadataBlock);
  const targetSub = parseSubKeys(targetMetadataBlock);
  const merged = new Map([...targetSub, ...mainSub]);

  return ['metadata:', ...merged.values()].join('\n');
}

/**
 * Deterministically merges frontmatter from `main` into a target `SKILL.md`,
 * preserving the target's Android-specific `description` while taking all
 * other frontmatter blocks (`name`, `version`, `compatibility`, `metadata`)
 * directly from `main` (and preserving any existing `metadata` sub-keys on target).
 */
function syncFrontmatterDeterministically(mainContent, targetContent) {
  const mainParts = splitFrontmatter(mainContent);
  const targetParts = splitFrontmatter(targetContent);
  if (!mainParts.rawFrontmatter) return targetContent;

  const mainBlocks = parseFrontmatterBlocks(mainParts.rawFrontmatter);
  const targetBlocks = parseFrontmatterBlocks(targetParts.rawFrontmatter);

  const mergedLines = [];
  for (const [key, blockText] of mainBlocks.entries()) {
    if (key === 'description' && targetBlocks.has('description')) {
      mergedLines.push(targetBlocks.get('description'));
    } else if (key === 'metadata') {
      mergedLines.push(mergeMetadataBlocks(blockText, targetBlocks.get('metadata')));
    } else {
      mergedLines.push(blockText);
    }
  }
  if (!mainBlocks.has('metadata') && targetBlocks.has('metadata')) {
    mergedLines.push(targetBlocks.get('metadata'));
  }

  return `---\n${mergedLines.join('\n')}\n---\n${targetParts.body}`;
}

function listFilesRecursive(dir, baseDir = dir) {
  if (!fs.existsSync(dir)) return [];
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath);
    if (entry.isDirectory()) {
      results.push(...listFilesRecursive(fullPath, baseDir));
    } else {
      results.push(relPath);
    }
  }
  return results.sort();
}

/**
 * Strips links pointing to excluded iOS/Web/Flutter local reference files
 * without touching JSON/code block trailing commas.
 */
function stripExcludedLocalLinks(markdown) {
  return markdown.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (match, _label, href) => {
    if (/^https?:\/\//i.test(href)) return match;
    const isExcluded = EXCLUDED_FILE_PATTERNS.some((pattern) =>
      pattern.test(href)
    );
    return isExcluded ? '' : match;
  });
}

async function rewriteSkillMdWithLLM({
  skillName,
  mainSkillMd,
  existingTargetSkillMd,
  survivingFiles,
  model,
}) {
  const precleaned = stripExcludedLocalLinks(mainSkillMd);
  const prompt = `You are maintaining the Android Studio distribution branch (\`platform/android-studio\`) of the \`firebase/agent-skills\` repository.
Your task is to adapt the upstream \`skills/${skillName}/SKILL.md\` file from \`main\` into an Android-focused \`SKILL.md\` for Android Studio.

### Surviving files in \`skills/${skillName}/\` on \`platform/android-studio\`:
${survivingFiles.map((f) => `- ${f}`).join('\n')}

### Strict Rules:
1. Preserve the YAML frontmatter keys (\`name\`, \`description\`, \`compatibility\`, \`version\`, \`metadata\`) from the upstream \`main\` file. In \`description\`, remove mentions of iOS/Xcode/Web/Flutter-only artifacts (e.g., \`GoogleService-Info.plist\`, Next.js, iOS, Flutter, Web) so it accurately describes Android and platform-agnostic capabilities.
2. Remove links to reference files that are NOT in the surviving files list above (such as iOS, Web, or Flutter setup/SDK guides).
3. Remove bullet points, table rows, or subsections that are exclusively for iOS, Web, or Flutter.
4. Rewrite sentences that list multiple client platforms so they refer to Android (and backend/admin/CLI where applicable) with natural, grammatically correct prose.
5. DO NOT alter any JSON examples, code blocks, CLI commands (other than removing iOS-only CLI flags/commands), or generic/Android instructions.
6. Output ONLY the complete markdown content of \`SKILL.md\` (starting with \`---\` and ending with the markdown body). Do not wrap the response in outer markdown code fences.

${
  existingTargetSkillMd
    ? `### Previous \`platform/android-studio\` version of \`skills/${skillName}/SKILL.md\` (for reference on how platform exclusions were previously styled):\n<<<<EXISTING\n${existingTargetSkillMd}\nEXISTING>>>>\n`
    : ''
}
### Upstream \`main\` version of \`skills/${skillName}/SKILL.md\` (with links to deleted local files stripped):
<<<<UPSTREAM
${precleaned}
UPSTREAM>>>>`;

  const result = await model.generateContent(prompt);
  let output = result.response.text();

  // Strip accidental outer ```markdown ... ``` fences if the model added them
  output = output.replace(/^```(?:markdown|yaml)?\r?\n/i, '').replace(/\r?\n```\s*$/, '');
  if (!output.endsWith('\n')) {
    output += '\n';
  }

  // Ensure non-description frontmatter blocks (metadata, version, compatibility, name) match main exactly
  return syncFrontmatterDeterministically(mainSkillMd, output);
}

/**
 * Checks if `description` or markdown `body` changed between `beforeSha` and current `mainContent`.
 * If only non-prose frontmatter fields (e.g. `metadata`, `version`, `compatibility`) changed,
 * returns false so Category 2 can deterministically sync frontmatter without calling the LLM.
 */
function didProseOrDescriptionChange(repoRoot, beforeSha, skillMdRepoPath, mainContent) {
  if (!beforeSha || /^0+$/.test(beforeSha)) return true;
  try {
    const prevContent = execFileSync(
      'git',
      ['-C', repoRoot, 'show', `${beforeSha}:${skillMdRepoPath}`],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const prevParts = splitFrontmatter(prevContent);
    const currParts = splitFrontmatter(mainContent);
    if (prevParts.body !== currParts.body) return true;

    const prevBlocks = parseFrontmatterBlocks(prevParts.rawFrontmatter);
    const currBlocks = parseFrontmatterBlocks(currParts.rawFrontmatter);
    return (prevBlocks.get('description') || '') !== (currBlocks.get('description') || '');
  } catch {
    // File didn't exist at beforeSha or git revision unavailable
    return true;
  }
}

async function main() {
  const args = process.argv.slice(2);
  let sourceDir = path.resolve(__dirname, '../skills');
  let targetDir = path.resolve(__dirname, '../android-skills');
  let fullResync = false;
  let changedFilesArg = '';
  let beforeSha = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--source-dir') {
      sourceDir = path.resolve(args[++i]);
    } else if (args[i] === '--target-dir') {
      targetDir = path.resolve(args[++i]);
    } else if (args[i] === '--full') {
      fullResync = true;
    } else if (args[i] === '--changed-files') {
      changedFilesArg = args[++i] || '';
    } else if (args[i] === '--before-sha') {
      beforeSha = args[++i] || '';
    }
  }

  const repoRoot = path.resolve(sourceDir, '..');
  const changedFiles = new Set(
    changedFilesArg
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
  );

  // Lazy-initialize Gemini model only if a Category 3 (SKILL.md body) LLM rewrite is needed
  let geminiModel = null;
  const getGeminiModel = async () => {
    if (geminiModel) return geminiModel;
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error(
        'GEMINI_API_KEY environment variable is required when SKILL.md prose changes require LLM adaptation.'
      );
    }
    const { GoogleGenerativeAI } = requireFromTokenCounter('@google/generative-ai');
    const modelName = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    const genAI = new GoogleGenerativeAI(apiKey);
    geminiModel = genAI.getGenerativeModel({ model: modelName });
    return geminiModel;
  };

  fs.mkdirSync(targetDir, { recursive: true });

  // Category 1a: Remove excluded skills or skills deleted from main
  const sourceSkills = new Set(
    fs
      .readdirSync(sourceDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
  );

  for (const existing of fs.readdirSync(targetDir, { withFileTypes: true })) {
    if (
      existing.isDirectory() &&
      (!sourceSkills.has(existing.name) || EXCLUDED_SKILLS.has(existing.name))
    ) {
      console.log(`[Category 1] Removing excluded/deleted skill: ${existing.name}`);
      fs.rmSync(path.join(targetDir, existing.name), { recursive: true, force: true });
    }
  }

  for (const skill of Array.from(sourceSkills).sort()) {
    if (EXCLUDED_SKILLS.has(skill)) {
      console.log(`[Category 1] Skipping excluded skill: ${skill}`);
      continue;
    }

    const srcSkillDir = path.join(sourceDir, skill);
    const destSkillDir = path.join(targetDir, skill);
    fs.mkdirSync(destSkillDir, { recursive: true });

    const allSrcFiles = listFilesRecursive(srcSkillDir);
    const survivingFiles = [];

    // Category 1b & Category 2: Filter excluded reference files, copy surviving non-SKILL.md files 1:1
    for (const relFile of allSrcFiles) {
      if (shouldExcludeFile(relFile)) {
        const destFile = path.join(destSkillDir, relFile);
        if (fs.existsSync(destFile)) {
          console.log(`[Category 1] Removing excluded file: ${skill}/${relFile}`);
          fs.rmSync(destFile, { force: true });
        }
        continue;
      }

      survivingFiles.push(relFile);
      if (relFile === 'SKILL.md') continue;

      const srcFile = path.join(srcSkillDir, relFile);
      const destFile = path.join(destSkillDir, relFile);
      fs.mkdirSync(path.dirname(destFile), { recursive: true });
      fs.copyFileSync(srcFile, destFile);
    }

    // Prune any stale files in destSkillDir that no longer exist in srcSkillDir
    for (const destRelFile of listFilesRecursive(destSkillDir)) {
      if (destRelFile === 'SKILL.md') continue;
      if (!survivingFiles.includes(destRelFile)) {
        console.log(`[Category 1] Pruning deleted upstream file: ${skill}/${destRelFile}`);
        fs.rmSync(path.join(destSkillDir, destRelFile), { force: true });
      }
    }

    // Category 2 vs Category 3 for SKILL.md
    const srcSkillMdPath = path.join(srcSkillDir, 'SKILL.md');
    const destSkillMdPath = path.join(destSkillDir, 'SKILL.md');
    if (!fs.existsSync(srcSkillMdPath)) continue;

    const mainSkillMd = fs.readFileSync(srcSkillMdPath, 'utf8');
    const existingTargetSkillMd = fs.existsSync(destSkillMdPath)
      ? fs.readFileSync(destSkillMdPath, 'utf8')
      : null;

    const skillMdRepoPath = `skills/${skill}/SKILL.md`;
    const fileInChangedSet =
      fullResync ||
      !existingTargetSkillMd ||
      changedFiles.size === 0 ||
      changedFiles.has(skillMdRepoPath);

    const needsLlmRewrite =
      fullResync ||
      !existingTargetSkillMd ||
      (fileInChangedSet &&
        didProseOrDescriptionChange(repoRoot, beforeSha, skillMdRepoPath, mainSkillMd));

    if (!needsLlmRewrite && existingTargetSkillMd) {
      const synced = syncFrontmatterDeterministically(mainSkillMd, existingTargetSkillMd);
      if (synced !== existingTargetSkillMd) {
        console.log(`[Category 2] Deterministically synced frontmatter for ${skill}/SKILL.md`);
        fs.writeFileSync(destSkillMdPath, synced, 'utf8');
      } else {
        console.log(`[Category 2] Keeping existing ${skill}/SKILL.md (unchanged)`);
      }
      continue;
    }

    console.log(`[Category 3] Adapting ${skill}/SKILL.md with Gemini...`);
    const model = await getGeminiModel();
    const adaptedSkillMd = await rewriteSkillMdWithLLM({
      skillName: skill,
      mainSkillMd,
      existingTargetSkillMd,
      survivingFiles,
      model,
    });
    fs.writeFileSync(destSkillMdPath, adaptedSkillMd, 'utf8');
  }

  console.log('Sync complete!');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
