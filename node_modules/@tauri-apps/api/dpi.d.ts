/**
 * A size represented in logical pixels.
 *
 * @since 2.0.0
 */
declare class LogicalSize {
    type: string;
    width: number;
    height: number;
    constructor(width: number, height: number);
    /**
     * Converts the logical size to a physical one.
     * @example
     * ```typescript
     * import { getCurrentWindow } from '@tauri-apps/api/window';
     * const appWindow = getCurrentWindow();
     * const factor = await appWindow.scaleFactor();
     * const size = new LogicalSize(400, 500);
     * const physical = size.toPhysical(factor);
     * ```
     *
     * @since 2.0.0
     */
    toPhysical(scaleFactor: number): PhysicalSize;
}
/**
 * A size represented in physical pixels.
 *
 * @since 2.0.0
 */
declare class PhysicalSize {
    type: string;
    width: number;
    height: number;
    constructor(width: number, height: number);
    /**
     * Converts the physical size to a logical one.
     * @example
     * ```typescript
     * import { getCurrentWindow } from '@tauri-apps/api/window';
     * const appWindow = getCurrentWindow();
     * const factor = await appWindow.scaleFactor();
     * const size = await appWindow.innerSize();
     * const logical = size.toLogical(factor);
     * ```
     */
    toLogical(scaleFactor: number): LogicalSize;
}
/**
 *  A position represented in logical pixels.
 *
 * @since 2.0.0
 */
declare class LogicalPosition {
    type: string;
    x: number;
    y: number;
    constructor(x: number, y: number);
    /**
     * Converts the logical position to a physical one.
     * @example
     * ```typescript
     * import { getCurrentWindow } from '@tauri-apps/api/window';
     * const appWindow = getCurrentWindow();
     * const factor = await appWindow.scaleFactor();
     * const position = new LogicalPosition(400, 500);
     * const physical = position.toPhysical(factor);
     * ```
     *
     * @since 2.0.0
     */
    toPhysical(scaleFactor: number): PhysicalPosition;
}
/**
 *  A position represented in physical pixels.
 *
 * @since 2.0.0
 */
declare class PhysicalPosition {
    type: string;
    x: number;
    y: number;
    constructor(x: number, y: number);
    /**
     * Converts the physical position to a logical one.
     * @example
     * ```typescript
     * import { getCurrentWindow } from '@tauri-apps/api/window';
     * const appWindow = getCurrentWindow();
     * const factor = await appWindow.scaleFactor();
     * const position = await appWindow.innerPosition();
     * const logical = position.toLogical(factor);
     * ```
     */
    toLogical(scaleFactor: number): LogicalPosition;
}
export { LogicalPosition, LogicalSize, PhysicalPosition, PhysicalSize };
