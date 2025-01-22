import { ShadowlessElement, SurfaceSelection } from '@blocksuite/block-std';
import type { NoteBlockModel } from '@blocksuite/blocks';
import {
  BlocksUtils,
  matchFlavours,
  NoteDisplayMode,
} from '@blocksuite/blocks';
import {
  Bound,
  DisposableGroup,
  SignalWatcher,
  WithDisposable,
} from '@blocksuite/global/utils';
import { consume } from '@lit/context';
import { effect, signal } from '@preact/signals-core';
import { html, nothing, type PropertyValues } from 'lit';
import { property, query } from 'lit/decorators.js';
import { classMap } from 'lit/directives/class-map.js';
import { repeat } from 'lit/directives/repeat.js';
import { when } from 'lit/directives/when.js';

import type { AffineEditorContainer } from '../../../editors/editor-container';
import { editorContext } from '../config';
import type {
  ClickBlockEvent,
  DisplayModeChangeEvent,
  FitViewEvent,
  SelectEvent,
} from '../utils/custom-events';
import { startDragging } from '../utils/drag';
import {
  getHeadingBlocksFromDoc,
  getNotesFromDoc,
  isHeadingBlock,
} from '../utils/query';
import {
  observeActiveHeadingDuringScroll,
  scrollToBlockWithHighlight,
} from '../utils/scroll';
import * as styles from './outline-panel-body.css';

type OutlineNoteItem = {
  note: NoteBlockModel;

  /**
   * the index of the note inside its parent's children property
   */
  index: number;

  /**
   * the number displayed on the outline panel
   */
  number: number;
};

export const AFFINE_OUTLINE_PANEL_BODY = 'affine-outline-panel-body';

export class OutlinePanelBody extends SignalWatcher(
  WithDisposable(ShadowlessElement)
) {
  private readonly _activeHeadingId$ = signal<string | null>(null);

  private readonly _dragging$ = signal(false);

  private readonly _pageVisibleNoteItems$ = signal<OutlineNoteItem[]>([]);

  private readonly _edgelessOnlyNoteItems$ = signal<OutlineNoteItem[]>([]);

  private _clearHighlightMask = () => {};

  private _docDisposables: DisposableGroup | null = null;

  private _indicatorTranslateY = 0;

  private _lockActiveHeadingId = false;

  private get _shouldRenderEmptyPanel() {
    return (
      this._pageVisibleNoteItems$.value.length === 0 &&
      this._edgelessOnlyNoteItems$.value.length === 0
    );
  }

  private get doc() {
    return this.editor.doc;
  }

  private get edgeless() {
    return this.editor.querySelector('affine-edgeless-root');
  }

  get viewportPadding(): [number, number, number, number] {
    return this.fitPadding
      ? ([0, 0, 0, 0].map((val, idx) =>
          Number.isFinite(this.fitPadding[idx]) ? this.fitPadding[idx] : val
        ) as [number, number, number, number])
      : [0, 0, 0, 0];
  }

  private _clearDocDisposables() {
    this._docDisposables?.dispose();
    this._docDisposables = null;
  }

  private _deSelectNoteInEdgelessMode(note: NoteBlockModel) {
    if (!this.edgeless) return;

    const { selection } = this.edgeless.service;
    if (!selection.has(note.id)) return;
    const selectedIds = selection.selectedIds.filter(id => id !== note.id);
    selection.set({
      elements: selectedIds,
      editing: false,
    });
  }

  /*
   * Double click at blank area to disable notes sorting option
   */
  private readonly _doubleClickHandler = (e: MouseEvent) => {
    e.stopPropagation();
    // check if click at outline-card, if so, do nothing
    if (
      (e.target as HTMLElement).closest('outline-note-card') ||
      !this.enableNotesSorting
    ) {
      return;
    }

    this.toggleNotesSorting();
  };

  private _drag() {
    const pageVisibleNotes = this._pageVisibleNoteItems$.peek();

    const selectedVisibleNotes = this._selectedNotes$.peek().filter(id => {
      const model = this.doc.getBlock(id)?.model;
      return (
        model &&
        matchFlavours(model, ['affine:note']) &&
        model.displayMode !== NoteDisplayMode.EdgelessOnly
      );
    });

    if (
      selectedVisibleNotes.length === 0 ||
      !pageVisibleNotes.length ||
      !this.doc.root
    )
      return;

    if (this.edgeless) {
      this.edgeless.service.selection.set({
        elements: selectedVisibleNotes,
        editing: false,
      });
    } else {
      this._selectedNotes$.value = selectedVisibleNotes;
    }

    this._dragging$.value = true;

    // cache the notes in case it is changed by other peers
    const children = this.doc.root.children.slice() as NoteBlockModel[];
    const notesMap = pageVisibleNotes.reduce((map, note, index) => {
      map.set(note.note.id, {
        ...note,
        number: index + 1,
      });
      return map;
    }, new Map<string, OutlineNoteItem>());

    startDragging({
      container: this,
      document: this.ownerDocument,
      host: this.ownerDocument,
      doc: this.doc,
      outlineListContainer: this._pageVisibleList,
      onDragEnd: insertIdx => {
        this._dragging$.value = false;
        this.insertIndex = undefined;

        if (insertIdx === undefined) return;

        this._moveNotes(
          insertIdx,
          selectedVisibleNotes,
          notesMap,
          pageVisibleNotes,
          children
        );
      },
      onDragMove: (idx, indicatorTranslateY) => {
        this.insertIndex = idx;
        this._indicatorTranslateY = indicatorTranslateY ?? 0;
      },
    });
  }

  private _EmptyPanel() {
    return html`<div class=${styles.emptyPanel}>
      <div
        data-testid="empty-panel-placeholder"
        class=${styles.emptyPanelPlaceholder}
      >
        Use headings to create a table of contents.
      </div>
    </div>`;
  }

  private _fitToElement(e: FitViewEvent) {
    const edgeless = this.edgeless;

    if (!edgeless) return;

    const { block } = e.detail;
    const bound = Bound.deserialize(block.xywh);

    edgeless.service.viewport.setViewportByBound(
      bound,
      this.viewportPadding,
      true
    );
  }

  // when display mode change to page only, we should de-select the note if it is selected in edgeless mode
  private _handleDisplayModeChange(e: DisplayModeChangeEvent) {
    const { note, newMode } = e.detail;
    const { displayMode: currentMode } = note;
    if (newMode === currentMode) {
      return;
    }

    this.doc.updateBlock(note, { displayMode: newMode });

    const noteParent = this.doc.getParent(note);
    if (noteParent === null) {
      console.error(`Failed to get parent of note(id:${note.id})`);
      return;
    }

    const noteParentChildNotes = noteParent.children.filter(block =>
      BlocksUtils.matchFlavours(block, ['affine:note'])
    ) as NoteBlockModel[];
    const noteParentLastNote =
      noteParentChildNotes[noteParentChildNotes.length - 1];

    // When the display mode of a note change from edgeless to page visible
    // We should move the note to the end of the note list
    if (
      currentMode === NoteDisplayMode.EdgelessOnly &&
      note !== noteParentLastNote
    ) {
      this.doc.moveBlocks([note], noteParent, noteParentLastNote, false);
    }

    // When the display mode of a note changed to page only
    // We should check if the note is selected in edgeless mode
    // If so, we should de-select it
    if (newMode === NoteDisplayMode.DocOnly) {
      this._deSelectNoteInEdgelessMode(note);
    }
  }

  private _moveNotes(
    index: number,
    selected: string[],
    notesMap: Map<string, OutlineNoteItem>,
    notes: OutlineNoteItem[],
    children: NoteBlockModel[]
  ) {
    if (!children.length || !this.doc.root) return;

    const blocks = selected.map(
      id => (notesMap.get(id) as OutlineNoteItem).note
    );
    const draggingBlocks = new Set(blocks);
    const targetIndex =
      index === notes.length ? notes[index - 1].index + 1 : notes[index].index;

    const leftPart = children
      .slice(0, targetIndex)
      .filter(block => !draggingBlocks.has(block));
    const rightPart = children
      .slice(targetIndex)
      .filter(block => !draggingBlocks.has(block));
    const newChildren = [...leftPart, ...blocks, ...rightPart];

    this.doc.updateBlock(this.doc.root, {
      children: newChildren,
    });
  }

  private _renderDocTitle() {
    if (!this.doc.root) return nothing;

    const hasNotEmptyHeadings =
      getHeadingBlocksFromDoc(
        this.doc,
        [NoteDisplayMode.DocOnly, NoteDisplayMode.DocAndEdgeless],
        true
      ).length > 0;

    if (!hasNotEmptyHeadings) return nothing;

    return html`<affine-outline-block-preview
      class=${classMap({
        active: this.doc.root.id === this._activeHeadingId$.value,
      })}
      .block=${this.doc.root}
      .className=${this.doc.root?.id === this._activeHeadingId$.value
        ? 'active'
        : ''}
      .cardNumber=${1}
      .enableNotesSorting=${false}
      .showPreviewIcon=${this.showPreviewIcon}
      @click=${() => {
        if (!this.doc.root) return;
        this._scrollToBlock(this.doc.root.id).catch(console.error);
      }}
    ></affine-outline-block-preview>`;
  }

  private _renderNoteCards(items: OutlineNoteItem[]) {
    return repeat(
      items,
      item => item.note.id,
      (item, idx) =>
        html`<affine-outline-note-card
          data-note-id=${item.note.id}
          .note=${item.note}
          .number=${idx + 1}
          .index=${item.index}
          .activeHeadingId=${this._activeHeadingId$.value}
          .showPreviewIcon=${this.showPreviewIcon}
          .enableNotesSorting=${this.enableNotesSorting}
          .status=${this._selectedNotes$.value.includes(item.note.id)
            ? this._dragging$.value
              ? 'placeholder'
              : 'selected'
            : 'normal'}
          @fitview=${this._fitToElement}
          @select=${this._selectNote}
          @displaymodechange=${this._handleDisplayModeChange}
          @drag=${this._drag}
          @clickblock=${(e: ClickBlockEvent) => {
            this._scrollToBlock(e.detail.blockId).catch(console.error);
          }}
        ></affine-outline-note-card>`
    );
  }

  private _renderPageVisibleCardList() {
    return html`<div class=${`page-visible-card-list ${styles.cardList}`}>
      ${when(
        this.insertIndex !== undefined,
        () =>
          html`<div
            class=${styles.insertIndicator}
            style=${`transform: translateY(${this._indicatorTranslateY}px)`}
          ></div>`
      )}
      ${this._renderNoteCards(this._pageVisibleNoteItems$.value)}
    </div>`;
  }

  private _renderEdgelessOnlyCardList() {
    const items = this._edgelessOnlyNoteItems$.value;
    return html`<div class=${styles.cardList}>
      ${when(
        items.length > 0,
        () =>
          html`<div class=${styles.edgelessCardListTitle}>Hidden Contents</div>`
      )}
      ${this._renderNoteCards(items)}
    </div>`;
  }

  private async _scrollToBlock(blockId: string) {
    this._lockActiveHeadingId = true;
    this._activeHeadingId$.value = blockId;
    this._clearHighlightMask = await scrollToBlockWithHighlight(
      this.editor,
      blockId
    );
    this._lockActiveHeadingId = false;
  }

  private readonly _selectedNotes$ = signal<string[]>([]);

  private _selectNote(e: SelectEvent) {
    const { selected, id, multiselect } = e.detail;

    let selectedNotes = this._selectedNotes$.peek();

    if (!selected) {
      selectedNotes = selectedNotes.filter(noteId => noteId !== id);
    } else if (multiselect) {
      selectedNotes = [...selectedNotes, id];
    } else {
      selectedNotes = [id];
    }

    if (this.edgeless) {
      this.edgeless?.service.selection.set({
        elements: selectedNotes,
        editing: false,
      });
    } else {
      this._selectedNotes$.value = selectedNotes;
    }
  }

  private _setDocDisposables() {
    this._clearDocDisposables();
    this._docDisposables = new DisposableGroup();
    this._docDisposables.add(
      effect(() => {
        this._updateNoticeVisibility();
      })
    );

    this._docDisposables.add(
      effect(() => {
        this._updateNotes();
      })
    );
  }

  private _updateNotes() {
    if (this._dragging$.value) return;

    const isRenderableNote = (item: OutlineNoteItem) => {
      let hasHeadings = false;

      for (const block of item.note.children) {
        if (isHeadingBlock(block)) {
          hasHeadings = true;
          break;
        }
      }

      return hasHeadings || this.enableNotesSorting;
    };

    this._pageVisibleNoteItems$.value = getNotesFromDoc(this.doc, [
      NoteDisplayMode.DocAndEdgeless,
      NoteDisplayMode.DocOnly,
    ]).filter(isRenderableNote);

    this._edgelessOnlyNoteItems$.value = getNotesFromDoc(this.doc, [
      NoteDisplayMode.EdgelessOnly,
    ]).filter(isRenderableNote);
  }

  private _updateNoticeVisibility() {
    if (this.enableNotesSorting) {
      if (this.noticeVisible) {
        this.setNoticeVisibility(false);
      }
      return;
    }

    const shouldShowNotice =
      getNotesFromDoc(this.doc, [NoteDisplayMode.DocOnly]).length > 0;

    if (shouldShowNotice && !this.noticeVisible) {
      this.setNoticeVisibility(true);
    }
  }

  private _watchSelectedNotes() {
    this.disposables.add(
      effect(() => {
        const { std, doc, mode } = this.editor;
        if (mode !== 'edgeless') return;

        const currSelectedNotes = std.selection
          .filter(SurfaceSelection)
          .filter(({ blockId }) => {
            const model = doc.getBlock(blockId)?.model;
            return !!model && matchFlavours(model, ['affine:note']);
          })
          .map(({ blockId }) => blockId);

        const preSelected = this._selectedNotes$.peek();
        if (
          preSelected.length !== currSelectedNotes.length ||
          preSelected.some(id => !currSelectedNotes.includes(id))
        ) {
          this._selectedNotes$.value = currSelectedNotes;
        }
      })
    );
  }

  override connectedCallback(): void {
    super.connectedCallback();
    this.classList.add(styles.outlinePanelBody);

    this.disposables.add(
      observeActiveHeadingDuringScroll(
        () => this.editor,
        newHeadingId => {
          if (this._lockActiveHeadingId) return;
          this._activeHeadingId$.value = newHeadingId;
        }
      )
    );
    this._watchSelectedNotes();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this._clearDocDisposables();
    this._clearHighlightMask();
  }

  override firstUpdated(): void {
    this.disposables.addFromEvent(this, 'dblclick', this._doubleClickHandler);
  }

  override render() {
    return html`
      ${this._renderDocTitle()}
      ${when(
        this._shouldRenderEmptyPanel,
        () => this._EmptyPanel(),
        () => html`
          ${this._renderPageVisibleCardList()}
          ${this._renderEdgelessOnlyCardList()}
        `
      )}
    `;
  }

  override willUpdate(_changedProperties: PropertyValues) {
    if (_changedProperties.has('editor')) {
      this._setDocDisposables();
    }

    if (_changedProperties.has('enableNotesSorting')) {
      this._updateNoticeVisibility();
    }
  }

  @query('.page-visible-card-list')
  private accessor _pageVisibleList!: HTMLElement;

  @consume({ context: editorContext })
  @property({ attribute: false })
  accessor editor!: AffineEditorContainer;

  @property({ attribute: false })
  accessor enableNotesSorting: boolean = false;

  @property({ attribute: false })
  accessor fitPadding!: number[];

  @property({ attribute: false })
  accessor insertIndex: number | undefined = undefined;

  @property({ attribute: false })
  accessor noticeVisible!: boolean;

  @property({ attribute: false })
  accessor renderEdgelessOnlyNotes: boolean = true;

  @property({ attribute: false })
  accessor setNoticeVisibility!: (visibility: boolean) => void;

  @property({ attribute: false })
  accessor showPreviewIcon!: boolean;

  @property({ attribute: false })
  accessor toggleNotesSorting!: () => void;
}

declare global {
  interface HTMLElementTagNameMap {
    [AFFINE_OUTLINE_PANEL_BODY]: OutlinePanelBody;
  }
}
