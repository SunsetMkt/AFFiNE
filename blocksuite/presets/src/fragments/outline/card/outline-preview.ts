import type { AffineTextAttributes } from '@blocksuite/affine-shared/types';
import { ShadowlessElement } from '@blocksuite/block-std';
import {
  type AttachmentBlockModel,
  type BookmarkBlockModel,
  type CodeBlockModel,
  type DatabaseBlockModel,
  DocDisplayMetaProvider,
  type ImageBlockModel,
  type ListBlockModel,
  type ParagraphBlockModel,
  type RootBlockModel,
} from '@blocksuite/blocks';
import { noop, SignalWatcher, WithDisposable } from '@blocksuite/global/utils';
import { LinkedPageIcon } from '@blocksuite/icons/lit';
import type { DeltaInsert } from '@blocksuite/inline';
import { consume } from '@lit/context';
import { html, nothing } from 'lit';
import { property } from 'lit/decorators.js';
import { classMap } from 'lit/directives/class-map.js';

import type { AffineEditorContainer } from '../../../editors/editor-container.js';
import { editorContext, placeholderMap, previewIconMap } from '../config.js';
import { isHeadingBlock, isRootBlock } from '../utils/query.js';
import * as styles from './outline-preview.css';

type ValuesOf<T, K extends keyof T = keyof T> = T[K];

function assertType<T>(value: unknown): asserts value is T {
  noop(value);
}

export const AFFINE_OUTLINE_BLOCK_PREVIEW = 'affine-outline-block-preview';

export class OutlineBlockPreview extends SignalWatcher(
  WithDisposable(ShadowlessElement)
) {
  private _TextBlockPreview(block: ParagraphBlockModel | ListBlockModel) {
    const deltas: DeltaInsert<AffineTextAttributes>[] =
      block.text.yText.toDelta();
    if (!block.text.length) return nothing;
    const iconClass = this.disabledIcon ? styles.iconDisabled : styles.icon;

    const previewText = deltas.map(delta => {
      if (delta.attributes?.reference) {
        // If linked doc, render linked doc icon and the doc title.
        const refAttribute = delta.attributes.reference;
        const refMeta = block.doc.workspace.meta.docMetas.find(
          doc => doc.id === refAttribute.pageId
        );
        const unavailable = !refMeta;
        const docDisplayMetaService = this.editor.std.get(
          DocDisplayMetaProvider
        );

        const icon = unavailable
          ? LinkedPageIcon({ width: '1.1em', height: '1.1em' })
          : docDisplayMetaService.icon(refMeta.id).value;
        const title = unavailable
          ? 'Deleted doc'
          : docDisplayMetaService.title(refMeta.id).value;

        return html`<span
          class=${classMap({
            [styles.linkedDocPreviewUnavailable]: unavailable,
          })}
        >
          ${icon}
          <span
            class=${classMap({
              [styles.linkedDocText]: true,
              [styles.linkedDocTextUnavailable]: unavailable,
            })}
            >${title.length ? title : 'Untitled'}</span
          ></span
        >`;
      } else {
        // If not linked doc, render the text.
        return delta.insert.toString().trim().length > 0
          ? html`<span class=${styles.textSpan}
              >${delta.insert.toString()}</span
            >`
          : nothing;
      }
    });

    const headingClass =
      block.type in styles.subtypeStyles
        ? styles.subtypeStyles[block.type as keyof typeof styles.subtypeStyles]
        : '';

    return html`<span
        data-testid="outline-block-preview-${block.type}"
        class="${styles.text} ${styles.textGeneral} ${headingClass}"
        >${previewText}</span
      >
      ${this.showPreviewIcon
        ? html`<span class=${iconClass}>${previewIconMap[block.type]}</span>`
        : nothing}`;
  }

  override render() {
    return html`<div class=${styles.outlineBlockPreview}>
      ${this.renderBlockByFlavour()}
    </div>`;
  }

  renderBlockByFlavour() {
    const { block } = this;
    const iconClass = this.disabledIcon ? styles.iconDisabled : styles.icon;

    if (
      !this.enableNotesSorting &&
      !isHeadingBlock(block) &&
      !isRootBlock(block)
    )
      return nothing;

    switch (block.flavour as keyof BlockSuite.BlockModels) {
      case 'affine:page':
        assertType<RootBlockModel>(block);
        return block.title.length > 0
          ? html`<span
              data-testid="outline-block-preview-title"
              class="${styles.text} ${styles.subtypeStyles.title}"
            >
              ${block.title$.value}
            </span>`
          : nothing;
      case 'affine:paragraph':
        assertType<ParagraphBlockModel>(block);
        return this._TextBlockPreview(block);
      case 'affine:list':
        assertType<ListBlockModel>(block);
        return this._TextBlockPreview(block);
      case 'affine:bookmark':
        assertType<BookmarkBlockModel>(block);
        return html`
          <span class="${styles.text} ${styles.textGeneral}"
            >${block.title || block.url || placeholderMap['bookmark']}</span
          >
          ${this.showPreviewIcon
            ? html`<span class=${iconClass}
                >${previewIconMap['bookmark']}</span
              >`
            : nothing}
        `;
      case 'affine:code':
        assertType<CodeBlockModel>(block);
        return html`
          <span class="${styles.text} ${styles.textGeneral}"
            >${block.language ?? placeholderMap['code']}</span
          >
          ${this.showPreviewIcon
            ? html`<span class=${iconClass}>${previewIconMap['code']}</span>`
            : nothing}
        `;
      case 'affine:database':
        assertType<DatabaseBlockModel>(block);
        return html`
          <span class="${styles.text} ${styles.textGeneral}"
            >${block.title.toString().length
              ? block.title.toString()
              : placeholderMap['database']}</span
          >
          ${this.showPreviewIcon
            ? html`<span class=${iconClass}>${previewIconMap['table']}</span>`
            : nothing}
        `;
      case 'affine:image':
        assertType<ImageBlockModel>(block);
        return html`
          <span class="${styles.text} ${styles.textGeneral}"
            >${block.caption?.length
              ? block.caption
              : placeholderMap['image']}</span
          >
          ${this.showPreviewIcon
            ? html`<span class=${iconClass}>${previewIconMap['image']}</span>`
            : nothing}
        `;
      case 'affine:attachment':
        assertType<AttachmentBlockModel>(block);
        return html`
          <span class="${styles.text} ${styles.textGeneral}"
            >${block.name?.length
              ? block.name
              : placeholderMap['attachment']}</span
          >
          ${this.showPreviewIcon
            ? html`<span class=${iconClass}
                >${previewIconMap['attachment']}</span
              >`
            : nothing}
        `;
      default:
        return nothing;
    }
  }

  @consume({ context: editorContext })
  @property({ attribute: false })
  accessor editor!: AffineEditorContainer;

  @property({ attribute: false })
  accessor block!: ValuesOf<BlockSuite.BlockModels>;

  @property({ attribute: false })
  accessor cardNumber!: number;

  @property({ attribute: false })
  accessor disabledIcon = false;

  @property({ attribute: false })
  accessor enableNotesSorting!: boolean;

  @property({ attribute: false })
  accessor showPreviewIcon!: boolean;
}

declare global {
  interface HTMLElementTagNameMap {
    [AFFINE_OUTLINE_BLOCK_PREVIEW]: OutlineBlockPreview;
  }
}
